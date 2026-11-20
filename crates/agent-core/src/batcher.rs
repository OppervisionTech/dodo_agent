//! Batcher — accumulates envelopes and flushes in batches.
//!
//! Implements HU014 (batching). Flushes when any of these conditions is met:
//! - Envelope count reaches `max_batch_size` (default 200)
//! - Timer expires (`flush_interval_ms`, default 5000ms)
//! - Shutdown signal (cancellation token)

use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{BatcherError, Envelope};

/// Configuration for the batcher.
#[derive(Debug, Clone)]
pub struct BatcherConfig {
    /// How often to flush an incomplete batch (milliseconds).
    pub flush_interval_ms: u32,

    /// Maximum number of envelopes per batch before a forced flush.
    pub max_batch_size: u32,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            flush_interval_ms: 5_000,
            max_batch_size: 200,
        }
    }
}

/// Run the batcher loop.
///
/// Receives individual envelopes from `envelope_rx` (fed by the scheduler),
/// accumulates them into batches, and sends complete batches to `batch_tx`
/// for the transport layer to pick up.
///
/// The batcher flushes when:
/// 1. The number of accumulated envelopes reaches `config.max_batch_size`.
/// 2. The flush timer (every `config.flush_interval_ms`) fires.
/// 3. The `cancel_token` is cancelled (graceful shutdown — flush remaining).
/// 4. The `envelope_rx` channel closes (all senders dropped).
///
/// # Arguments
///
/// * `envelope_rx` — bounded mpsc receiver of individual envelopes
/// * `batch_tx` — bounded mpsc sender of batched envelopes
/// * `config` — batcher configuration
/// * `cancel_token` — cancellation token for graceful shutdown
pub async fn run(
    mut envelope_rx: mpsc::Receiver<Envelope>,
    batch_tx: mpsc::Sender<Vec<Envelope>>,
    config: BatcherConfig,
    cancel_token: CancellationToken,
) -> Result<(), BatcherError> {
    let flush_interval = Duration::from_millis(config.flush_interval_ms as u64);
    let max_batch = config.max_batch_size as usize;

    let mut buffer: Vec<Envelope> = Vec::with_capacity(max_batch);
    let mut flush_timer = tokio::time::interval(flush_interval);
    flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Consume the first immediate tick so we don't flush an empty batch on start.
    flush_timer.tick().await;

    tracing::info!(
        flush_interval_ms = config.flush_interval_ms,
        max_batch_size = config.max_batch_size,
        "batcher started"
    );

    loop {
        tokio::select! {
            biased;

            // Priority 1: shutdown.
            () = cancel_token.cancelled() => {
                // Drain envelopes already queued so they are not lost on shutdown.
                while let Ok(envelope) = envelope_rx.try_recv() {
                    buffer.push(envelope);
                    if buffer.len() >= max_batch {
                        flush(&batch_tx, &mut buffer).await?;
                    }
                }
                tracing::info!(
                    remaining = buffer.len(),
                    "batcher shutting down, flushing remaining envelopes"
                );
                if !buffer.is_empty() {
                    flush(&batch_tx, &mut buffer).await?;
                }
                return Ok(());
            }

            // Priority 2: receive envelopes.
            maybe_envelope = envelope_rx.recv() => {
                match maybe_envelope {
                    Some(envelope) => {
                        buffer.push(envelope);
                        if buffer.len() >= max_batch {
                            flush(&batch_tx, &mut buffer).await?;
                        }
                    }
                    None => {
                        // All senders dropped — channel closed.
                        tracing::info!(
                            remaining = buffer.len(),
                            "envelope channel closed, flushing remaining"
                        );
                        if !buffer.is_empty() {
                            flush(&batch_tx, &mut buffer).await?;
                        }
                        return Ok(());
                    }
                }
            }

            // Priority 3: periodic flush timer.
            _ = flush_timer.tick() => {
                if !buffer.is_empty() {
                    flush(&batch_tx, &mut buffer).await?;
                }
            }
        }
    }
}

/// Drain `buffer` into a batch and send it downstream.
async fn flush(
    batch_tx: &mpsc::Sender<Vec<Envelope>>,
    buffer: &mut Vec<Envelope>,
) -> Result<(), BatcherError> {
    let batch: Vec<Envelope> = std::mem::take(buffer);
    let count = batch.len();

    tracing::debug!(batch_size = count, "flushing batch");

    batch_tx
        .send(batch)
        .await
        .map_err(|_| BatcherError::SendFailed("batch channel closed".into()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignalType;

    fn make_envelope(n: u8) -> Envelope {
        Envelope {
            signal_type: SignalType::Metric,
            payload: vec![n],
            timestamp_unix_ns: n as i64,
            buffered: false,
            retry_count: 0,
        }
    }

    #[tokio::test]
    async fn flushes_on_max_batch_size() {
        let (env_tx, env_rx) = mpsc::channel(1000);
        let (batch_tx, mut batch_rx) = mpsc::channel(100);
        let token = CancellationToken::new();

        let config = BatcherConfig {
            flush_interval_ms: 60_000, // very long — won't fire
            max_batch_size: 3,
        };

        let token2 = token.clone();
        let handle = tokio::spawn(run(env_rx, batch_tx, config, token.clone()));

        // Send exactly max_batch_size envelopes.
        for i in 0..3u8 {
            env_tx.send(make_envelope(i)).await.expect("send failed");
        }

        // Should get a batch of 3.
        let batch = tokio::time::timeout(Duration::from_secs(2), batch_rx.recv())
            .await
            .expect("timeout waiting for batch")
            .expect("channel closed");
        assert_eq!(batch.len(), 3);

        token2.cancel();
        handle.await.expect("join").expect("batcher error");
    }

    #[tokio::test]
    async fn flushes_on_timer() {
        let (env_tx, env_rx) = mpsc::channel(1000);
        let (batch_tx, mut batch_rx) = mpsc::channel(100);
        let token = CancellationToken::new();

        let config = BatcherConfig {
            flush_interval_ms: 100,
            max_batch_size: 1000, // very large — won't trigger by count
        };

        let token2 = token.clone();
        let handle = tokio::spawn(run(env_rx, batch_tx, config, token.clone()));

        // Send 2 envelopes (below max_batch_size).
        env_tx.send(make_envelope(1)).await.expect("send");
        env_tx.send(make_envelope(2)).await.expect("send");

        // Wait for the timer flush.
        let batch = tokio::time::timeout(Duration::from_secs(2), batch_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(batch.len(), 2);

        token2.cancel();
        handle.await.expect("join").expect("batcher error");
    }

    #[tokio::test]
    async fn flushes_remaining_on_shutdown() {
        let (env_tx, env_rx) = mpsc::channel(1000);
        let (batch_tx, mut batch_rx) = mpsc::channel(100);
        let token = CancellationToken::new();

        let config = BatcherConfig {
            flush_interval_ms: 60_000,
            max_batch_size: 1000,
        };

        let handle = tokio::spawn(run(env_rx, batch_tx, config, token.clone()));

        env_tx.send(make_envelope(1)).await.expect("send");

        // Small delay so the batcher loop has time to receive the envelope.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Signal shutdown.
        token.cancel();
        handle.await.expect("join").expect("batcher error");

        // The remaining envelope should have been flushed.
        let batch = batch_rx.try_recv().expect("expected a final flush batch");
        assert_eq!(batch.len(), 1);
    }
}
