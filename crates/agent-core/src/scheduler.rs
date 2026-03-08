//! Scheduler — runs each collector in its own tokio task at its configured interval.
//!
//! Part of HU013 (core loop, scheduler, collector trait).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use crate::registry::CollectorRegistry;
use crate::{AgentState, Collector, Envelope, SchedulerError};

/// Run all registered collectors on their individual intervals.
///
/// Each collector gets its own spawned task with a `tokio::time::interval`.
/// Envelopes produced by each collection pass are forwarded to `envelope_tx`.
///
/// The function returns when the `cancel_token` is cancelled (graceful
/// shutdown). All spawned tasks are automatically aborted via the `JoinSet`.
///
/// # Arguments
///
/// * `registry` — the collector registry (consumed; ownership moves here)
/// * `envelope_tx` — bounded mpsc sender for individual envelopes
/// * `cancel_token` — cancellation token for graceful shutdown
/// * `agent_state` — shared agent state for counters and identity
pub async fn run(
    registry: CollectorRegistry,
    envelope_tx: mpsc::Sender<Envelope>,
    cancel_token: CancellationToken,
    agent_state: AgentState,
) -> Result<(), SchedulerError> {
    let collectors = registry.into_collectors();

    if collectors.is_empty() {
        tracing::warn!("scheduler started with zero collectors — nothing to do");
        cancel_token.cancelled().await;
        return Ok(());
    }

    // Record active collector names.
    {
        let names: Vec<String> = collectors.iter().map(|c| c.name().to_owned()).collect();
        if let Ok(mut active) = agent_state.active_collectors.write() {
            *active = names;
        }
    }

    tracing::info!(
        collector_count = collectors.len(),
        "scheduler starting collectors"
    );

    let mut join_set: JoinSet<()> = JoinSet::new();

    for collector in collectors {
        let tx = envelope_tx.clone();
        let token = cancel_token.clone();
        let state = agent_state.clone();

        // Arc the collector so we can share it across tick iterations
        // within the same task.
        let collector: Arc<dyn Collector> = Arc::from(collector);

        join_set.spawn(run_collector(collector, tx, token, state));
    }

    // Drop our copy so that when all tasks finish the channel closes.
    drop(envelope_tx);

    // Wait for cancellation.
    cancel_token.cancelled().await;

    tracing::info!("scheduler received shutdown signal, aborting collector tasks");

    // Abort all running collector tasks.
    join_set.abort_all();

    // Drain join results (ignore errors — they are aborts).
    while join_set.join_next().await.is_some() {}

    tracing::info!("scheduler shutdown complete");
    Ok(())
}

/// Run a single collector in a loop until the cancellation token fires.
async fn run_collector(
    collector: Arc<dyn Collector>,
    envelope_tx: mpsc::Sender<Envelope>,
    cancel_token: CancellationToken,
    agent_state: AgentState,
) {
    let name = collector.name().to_owned();
    let interval_dur = collector.interval();

    // Timeout per collection is 2x the interval.
    let timeout_dur = interval_dur.saturating_mul(2);

    let mut interval = tokio::time::interval(interval_dur);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    tracing::debug!(
        collector = %name,
        interval_ms = interval_dur.as_millis() as u64,
        timeout_ms = timeout_dur.as_millis() as u64,
        "collector task started"
    );

    loop {
        tokio::select! {
            biased;

            () = cancel_token.cancelled() => {
                tracing::debug!(collector = %name, "collector task shutting down");
                return;
            }

            _ = interval.tick() => {
                let result = tokio::time::timeout(timeout_dur, collector.collect()).await;

                match result {
                    Ok(Ok(envelopes)) => {
                        let count = envelopes.len();
                        for envelope in envelopes {
                            if envelope_tx.send(envelope).await.is_err() {
                                // Channel closed — scheduler is shutting down.
                                tracing::debug!(
                                    collector = %name,
                                    "envelope channel closed, stopping collector"
                                );
                                return;
                            }
                        }
                        if count > 0 {
                            tracing::trace!(
                                collector = %name,
                                envelope_count = count,
                                "collection pass complete"
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        agent_state.collector_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            collector = %name,
                            error = %e,
                            "collection error, will retry next interval"
                        );
                    }
                    Err(_elapsed) => {
                        agent_state.collector_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            collector = %name,
                            timeout_ms = timeout_dur.as_millis() as u64,
                            "collection timed out, will retry next interval"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CollectorError, SignalType};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    struct TickCounter {
        count: Arc<AtomicU64>,
    }

    impl Collector for TickCounter {
        fn name(&self) -> &str {
            "tick_counter"
        }

        fn signal_type(&self) -> SignalType {
            SignalType::Metric
        }

        fn interval(&self) -> Duration {
            Duration::from_millis(50)
        }

        fn collect(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>>
        {
            let count = self.count.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::Relaxed);
                let env = Envelope {
                    signal_type: SignalType::Metric,
                    payload: vec![1, 2, 3],
                    timestamp_unix_ns: 12345,
                    buffered: false,
                    retry_count: 0,
                };
                Ok(vec![env])
            })
        }
    }

    fn test_state() -> AgentState {
        AgentState::new(
            "test".into(),
            "0.1.0".into(),
            "linux".into(),
            "host".into(),
            "hid".into(),
            "linux".into(),
        )
    }

    #[tokio::test]
    async fn scheduler_runs_collector_and_shuts_down() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut reg = CollectorRegistry::new();
        reg.register(Box::new(TickCounter {
            count: counter.clone(),
        }));

        let (tx, mut rx) = mpsc::channel(1000);
        let token = CancellationToken::new();
        let token2 = token.clone();

        let handle = tokio::spawn(run(reg, tx, token.clone(), test_state()));

        // Let the collector tick a few times.
        tokio::time::sleep(Duration::from_millis(180)).await;
        token2.cancel();

        handle
            .await
            .expect("scheduler panicked")
            .expect("scheduler error");

        // Should have received some envelopes.
        let mut received = 0;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        assert!(received >= 2, "expected >=2 envelopes, got {received}");
        assert!(counter.load(Ordering::Relaxed) >= 2);
    }
}
