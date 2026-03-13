//! CPU collector — HU019.
//!
//! Collects CPU utilization metrics at 5-second intervals by reading
//! platform CPU times and computing deltas between consecutive samples.
//! Also collects load averages, CPU counts, and cgroup CPU limits when
//! running inside a container.

use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::{CpuTimes, Platform};
use tokio::sync::Mutex;

use crate::helpers::metric_envelope;

/// Previous CPU sample for delta computation.
struct PreviousSample {
    aggregate: CpuTimes,
    per_core: Vec<CpuTimes>,
}

/// Collects CPU utilization metrics by computing deltas between consecutive
/// /proc/stat reads (or platform equivalent).
pub struct CpuCollector {
    platform: Arc<dyn Platform>,
    previous: Mutex<Option<PreviousSample>>,
}

impl CpuCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Self {
            platform,
            previous: Mutex::new(None),
        }
    }
}

impl Collector for CpuCollector {
    fn name(&self) -> &str {
        "cpu"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Metric
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            let mut envelopes = Vec::new();

            // ------------------------------------------------------------------
            // Read current CPU times (index 0 = aggregate, rest = per-core)
            // ------------------------------------------------------------------
            let cpu_times = self.platform.cpu_times()?;
            if cpu_times.is_empty() {
                return Err(CollectorError::Failed(
                    "cpu: no CPU time samples returned by platform".into(),
                ));
            }

            let aggregate = &cpu_times[0];
            let per_core = &cpu_times[1..];

            // ------------------------------------------------------------------
            // Delta calculation against previous sample
            // ------------------------------------------------------------------
            let mut prev_guard = self.previous.lock().await;

            if let Some(prev) = prev_guard.as_ref() {
                // Aggregate CPU usage
                let total_delta = aggregate.total().saturating_sub(prev.aggregate.total());
                if total_delta > 0 {
                    let td = total_delta as f64;
                    let busy_delta = aggregate.busy().saturating_sub(prev.aggregate.busy());
                    let user_delta = aggregate.user.saturating_sub(prev.aggregate.user);
                    let system_delta = aggregate.system.saturating_sub(prev.aggregate.system);
                    let iowait_delta = aggregate.iowait.saturating_sub(prev.aggregate.iowait);
                    let steal_delta = aggregate.steal.saturating_sub(prev.aggregate.steal);
                    let idle_delta = aggregate.idle.saturating_sub(prev.aggregate.idle);

                    envelopes.push(metric_envelope(
                        "cpu.usage.percent",
                        (busy_delta as f64 / td) * 100.0,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "cpu.usage.user_percent",
                        (user_delta as f64 / td) * 100.0,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "cpu.usage.system_percent",
                        (system_delta as f64 / td) * 100.0,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "cpu.usage.iowait_percent",
                        (iowait_delta as f64 / td) * 100.0,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "cpu.usage.steal_percent",
                        (steal_delta as f64 / td) * 100.0,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "cpu.usage.idle_percent",
                        (idle_delta as f64 / td) * 100.0,
                        &[],
                        "gauge",
                    ));
                }

                // Per-core usage
                let core_count = per_core.len().min(prev.per_core.len());
                for (i, (cur, prv)) in per_core
                    .iter()
                    .zip(prev.per_core.iter())
                    .enumerate()
                    .take(core_count)
                {
                    let core_total_delta = cur.total().saturating_sub(prv.total());
                    if core_total_delta > 0 {
                        let core_busy_delta = cur.busy().saturating_sub(prv.busy());
                        let core_label = i.to_string();
                        envelopes.push(metric_envelope(
                            "cpu.core.usage_percent",
                            (core_busy_delta as f64 / core_total_delta as f64) * 100.0,
                            &[("core", &core_label)],
                            "gauge",
                        ));
                    }
                }
            } else {
                tracing::debug!("cpu collector: first sample captured, deltas available next tick");
            }

            // Store current as previous for next tick
            *prev_guard = Some(PreviousSample {
                aggregate: aggregate.clone(),
                per_core: per_core.to_vec(),
            });
            drop(prev_guard);

            // ------------------------------------------------------------------
            // Load averages
            // ------------------------------------------------------------------
            match self.platform.load_average() {
                Ok(la) => {
                    envelopes.push(metric_envelope("cpu.load.1m", la.one, &[], "gauge"));
                    envelopes.push(metric_envelope("cpu.load.5m", la.five, &[], "gauge"));
                    envelopes.push(metric_envelope("cpu.load.15m", la.fifteen, &[], "gauge"));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read load average");
                }
            }

            // ------------------------------------------------------------------
            // CPU counts
            // ------------------------------------------------------------------
            match self.platform.info() {
                Ok(info) => {
                    envelopes.push(metric_envelope(
                        "cpu.count.logical",
                        info.cpu_count_logical as f64,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "cpu.count.physical",
                        info.cpu_count_physical as f64,
                        &[],
                        "gauge",
                    ));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read platform info for CPU counts");
                }
            }

            // ------------------------------------------------------------------
            // Cgroup CPU limits (container detection)
            // ------------------------------------------------------------------
            match self.platform.cgroup_cpu() {
                Ok(Some(cgroup)) => {
                    if cgroup.has_limit {
                        envelopes.push(metric_envelope(
                            "cpu.cgroup.limit_cores",
                            cgroup.limit_cores,
                            &[],
                            "gauge",
                        ));
                        envelopes.push(metric_envelope(
                            "cpu.cgroup.usage_ns",
                            cgroup.usage_ns as f64,
                            &[],
                            "counter",
                        ));
                    }
                }
                Ok(None) => { /* not in a cgroup, skip */ }
                Err(e) => {
                    tracing::trace!(error = %e, "cgroup CPU info not available");
                }
            }

            Ok(envelopes)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agent_platform::common::MockPlatform;

    #[tokio::test]
    async fn first_collection_returns_load_and_counts() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = CpuCollector::new(platform);

        let result = collector.collect().await;
        assert!(result.is_ok());
        let envelopes = result.unwrap();

        // First collection: no deltas, but should have load avg + cpu counts
        assert!(!envelopes.is_empty());

        let names: Vec<String> = envelopes
            .iter()
            .filter_map(|e| {
                let v: serde_json::Value = serde_json::from_slice(&e.payload).ok()?;
                v["name"].as_str().map(|s| s.to_string())
            })
            .collect();

        assert!(names.contains(&"cpu.load.1m".to_string()));
        assert!(names.contains(&"cpu.count.logical".to_string()));
    }

    #[tokio::test]
    async fn second_collection_still_has_load_and_counts() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = CpuCollector::new(platform);

        // First collection (baseline)
        let _ = collector.collect().await;
        // Second collection — mock returns identical values so delta is 0,
        // but load averages and CPU counts should still be present.
        let result = collector.collect().await;
        assert!(result.is_ok());
        let envelopes = result.unwrap();

        let names: Vec<String> = envelopes
            .iter()
            .filter_map(|e| {
                let v: serde_json::Value = serde_json::from_slice(&e.payload).ok()?;
                v["name"].as_str().map(|s| s.to_string())
            })
            .collect();

        assert!(names.contains(&"cpu.load.1m".to_string()));
        assert!(names.contains(&"cpu.count.logical".to_string()));
    }
}
