//! Memory collector — HU020.
//!
//! Collects memory and swap utilization metrics at 5-second intervals.
//! Reads /proc/meminfo (or platform equivalent) and optionally cgroup
//! memory limits when running inside a container.

use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;

use crate::helpers::metric_envelope;

/// Collects memory utilization metrics from the platform.
pub struct MemoryCollector {
    platform: Arc<dyn Platform>,
}

impl MemoryCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Self { platform }
    }
}

impl Collector for MemoryCollector {
    fn name(&self) -> &str {
        "memory"
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

            let mem = self.platform.memory_info()?;

            // ------------------------------------------------------------------
            // Physical memory
            // ------------------------------------------------------------------
            envelopes.push(metric_envelope(
                "memory.total.bytes",
                mem.total_bytes as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "memory.used.bytes",
                mem.used_bytes as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "memory.available.bytes",
                mem.available_bytes as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "memory.free.bytes",
                mem.free_bytes as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "memory.cached.bytes",
                mem.cached_bytes as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "memory.buffers.bytes",
                mem.buffers_bytes as f64,
                &[],
                "gauge",
            ));

            // Usage percent (used / total)
            let usage_percent = if mem.total_bytes > 0 {
                (mem.used_bytes as f64 / mem.total_bytes as f64) * 100.0
            } else {
                0.0
            };
            envelopes.push(metric_envelope(
                "memory.usage.percent",
                usage_percent,
                &[],
                "gauge",
            ));

            // ------------------------------------------------------------------
            // Swap
            // ------------------------------------------------------------------
            envelopes.push(metric_envelope(
                "memory.swap.total.bytes",
                mem.swap_total_bytes as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "memory.swap.used.bytes",
                mem.swap_used_bytes as f64,
                &[],
                "gauge",
            ));

            let swap_usage_percent = if mem.swap_total_bytes > 0 {
                (mem.swap_used_bytes as f64 / mem.swap_total_bytes as f64) * 100.0
            } else {
                0.0
            };
            envelopes.push(metric_envelope(
                "memory.swap.usage.percent",
                swap_usage_percent,
                &[],
                "gauge",
            ));

            // ------------------------------------------------------------------
            // Huge pages
            // ------------------------------------------------------------------
            envelopes.push(metric_envelope(
                "memory.hugepages.total",
                mem.hugepages_total as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "memory.hugepages.free",
                mem.hugepages_free as f64,
                &[],
                "gauge",
            ));

            // ------------------------------------------------------------------
            // Cgroup memory limits (container detection)
            // ------------------------------------------------------------------
            match self.platform.cgroup_memory() {
                Ok(Some(cgroup)) => {
                    if cgroup.has_limit {
                        envelopes.push(metric_envelope(
                            "memory.cgroup.limit.bytes",
                            cgroup.limit_bytes as f64,
                            &[],
                            "gauge",
                        ));
                        envelopes.push(metric_envelope(
                            "memory.cgroup.usage.bytes",
                            cgroup.usage_bytes as f64,
                            &[],
                            "gauge",
                        ));
                        let cgroup_percent = if cgroup.limit_bytes > 0 {
                            (cgroup.usage_bytes as f64 / cgroup.limit_bytes as f64) * 100.0
                        } else {
                            0.0
                        };
                        envelopes.push(metric_envelope(
                            "memory.cgroup.usage.percent",
                            cgroup_percent,
                            &[],
                            "gauge",
                        ));
                    }
                }
                Ok(None) => { /* not in a cgroup, skip */ }
                Err(e) => {
                    tracing::trace!(error = %e, "cgroup memory info not available");
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
    async fn collects_memory_metrics() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = MemoryCollector::new(platform);

        let result = collector.collect().await;
        assert!(result.is_ok());
        let envelopes = result.unwrap();

        // Should have at least the 12 base memory metrics
        assert!(envelopes.len() >= 12);

        let names: Vec<String> = envelopes
            .iter()
            .filter_map(|e| {
                let v: serde_json::Value = serde_json::from_slice(&e.payload).ok()?;
                v["name"].as_str().map(|s| s.to_string())
            })
            .collect();

        assert!(names.contains(&"memory.total.bytes".to_string()));
        assert!(names.contains(&"memory.used.bytes".to_string()));
        assert!(names.contains(&"memory.available.bytes".to_string()));
        assert!(names.contains(&"memory.usage.percent".to_string()));
        assert!(names.contains(&"memory.swap.total.bytes".to_string()));
        assert!(names.contains(&"memory.hugepages.total".to_string()));
    }

    #[tokio::test]
    async fn usage_percent_is_sane() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = MemoryCollector::new(platform);

        let envelopes = collector.collect().await.unwrap();
        let usage_env = envelopes.iter().find(|e| {
            let v: serde_json::Value = serde_json::from_slice(&e.payload).unwrap_or_default();
            v["name"].as_str() == Some("memory.usage.percent")
        });

        assert!(usage_env.is_some());
        let v: serde_json::Value = serde_json::from_slice(&usage_env.unwrap().payload).unwrap();
        let pct = v["value"].as_f64().unwrap();
        assert!(pct >= 0.0 && pct <= 100.0);
    }
}
