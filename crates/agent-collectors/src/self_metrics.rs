//! Self-metrics collector — HU030.
//!
//! Reports the agent's own resource consumption and internal counters
//! at 30-second intervals. Reads /proc/self/stat and /proc/self/status
//! on Linux to measure own CPU and memory usage. Warns when the agent
//! exceeds its resource budgets (5% CPU, configurable memory).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use agent_core::{AgentState, Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;

use crate::helpers::metric_envelope;

/// CPU usage threshold (percent) above which we log a warning.
const CPU_WARN_THRESHOLD: f64 = 5.0;

/// Default memory warning threshold in MB.
const MEMORY_WARN_THRESHOLD_MB: f64 = 50.0;

/// Collects the agent's own resource usage and internal counters.
pub struct SelfMetricsCollector {
    platform: Arc<dyn Platform>,
    state: Arc<AgentState>,
    memory_warn_mb: f64,
}

impl SelfMetricsCollector {
    /// Create a new self-metrics collector.
    ///
    /// - `state`: Shared agent state with counters.
    /// - `memory_warn_mb`: Memory warning threshold in MB. Defaults to 50.
    pub fn new(
        platform: Arc<dyn Platform>,
        state: Arc<AgentState>,
        memory_warn_mb: Option<f64>,
    ) -> Self {
        Self {
            platform,
            state,
            memory_warn_mb: memory_warn_mb.unwrap_or(MEMORY_WARN_THRESHOLD_MB),
        }
    }

    /// Read agent's own CPU and memory from /proc/self on Linux.
    /// Returns (cpu_percent, memory_bytes). On non-Linux or error, returns (0.0, 0).
    fn read_self_proc(&self) -> (f64, u64) {
        // Try to read /proc/self/status for VmRSS
        let memory_bytes = match self.platform.read_file_string("/proc/self/status") {
            Ok(content) => Self::parse_vm_rss(&content).unwrap_or(0),
            Err(_) => 0,
        };

        // CPU usage from /proc/self/stat is complex to compute as a percentage
        // (needs delta of utime+stime vs wall clock). For MVP, we approximate
        // using the process list and finding ourselves.
        let cpu_percent = match self.platform.processes() {
            Ok(procs) => {
                let my_pid = std::process::id();
                procs
                    .iter()
                    .find(|p| p.pid == my_pid)
                    .map(|p| p.cpu_percent)
                    .unwrap_or(0.0)
            }
            Err(_) => 0.0,
        };

        (cpu_percent, memory_bytes)
    }

    /// Parse VmRSS from /proc/self/status content.
    fn parse_vm_rss(content: &str) -> Option<u64> {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return Some(kb * 1024); // Convert KB to bytes
                    }
                }
            }
        }
        None
    }
}

impl Collector for SelfMetricsCollector {
    fn name(&self) -> &str {
        "self_metrics"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Metric
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            let mut envelopes = Vec::new();

            // ------------------------------------------------------------------
            // Agent resource consumption
            // ------------------------------------------------------------------
            let (cpu_percent, memory_bytes) = self.read_self_proc();
            let memory_mb = memory_bytes as f64 / (1024.0 * 1024.0);

            envelopes.push(metric_envelope(
                "agent.cpu.usage_percent",
                cpu_percent,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "agent.memory.usage_bytes",
                memory_bytes as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "agent.memory.usage_mb",
                memory_mb,
                &[],
                "gauge",
            ));

            // Warn if exceeding thresholds
            if cpu_percent > CPU_WARN_THRESHOLD {
                tracing::warn!(
                    cpu_percent = cpu_percent,
                    threshold = CPU_WARN_THRESHOLD,
                    "agent CPU usage exceeds threshold"
                );
            }
            if memory_mb > self.memory_warn_mb {
                tracing::warn!(
                    memory_mb = memory_mb,
                    threshold = self.memory_warn_mb,
                    "agent memory usage exceeds threshold"
                );
            }

            // ------------------------------------------------------------------
            // Internal counters from AgentState
            // ------------------------------------------------------------------
            let sent = self.state.envelopes_sent.load(Ordering::Relaxed);
            let failed = self.state.envelopes_failed.load(Ordering::Relaxed);
            let collector_errors = self.state.collector_errors.load(Ordering::Relaxed);
            let redactions = self.state.redactions_total.load(Ordering::Relaxed);
            let buffer_used = self.state.buffer_used_bytes.load(Ordering::Relaxed);

            envelopes.push(metric_envelope(
                "agent.envelopes.sent_total",
                sent as f64,
                &[],
                "counter",
            ));
            envelopes.push(metric_envelope(
                "agent.envelopes.failed_total",
                failed as f64,
                &[],
                "counter",
            ));

            // Buffer usage
            envelopes.push(metric_envelope(
                "agent.buffer.used_bytes",
                buffer_used as f64,
                &[],
                "gauge",
            ));

            // Buffer usage percent (assume 512MB default)
            let buffer_limit: f64 = 512.0 * 1024.0 * 1024.0;
            let buffer_pct = (buffer_used as f64 / buffer_limit) * 100.0;
            envelopes.push(metric_envelope(
                "agent.buffer.percent",
                buffer_pct.min(100.0),
                &[],
                "gauge",
            ));

            // Active collectors count
            let active_count = {
                let guard = self
                    .state
                    .active_collectors
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                guard.len() as f64
            };
            envelopes.push(metric_envelope(
                "agent.collectors.active_count",
                active_count,
                &[],
                "gauge",
            ));

            envelopes.push(metric_envelope(
                "agent.collectors.errors_total",
                collector_errors as f64,
                &[],
                "counter",
            ));

            // Uptime
            envelopes.push(metric_envelope(
                "agent.uptime_seconds",
                self.state.uptime_seconds() as f64,
                &[],
                "gauge",
            ));

            // Redactions
            envelopes.push(metric_envelope(
                "agent.redactions.total",
                redactions as f64,
                &[],
                "counter",
            ));

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
    use crate::helpers::MetricPayload;
    use agent_platform::common::MockPlatform;
    use prost::Message;

    fn test_state() -> Arc<AgentState> {
        Arc::new(AgentState::new(
            "test-id".into(),
            "0.1.0".into(),
            "linux".into(),
            "test-host".into(),
            "test-host-id".into(),
            "linux".into(),
        ))
    }

    #[tokio::test]
    async fn collects_self_metrics() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let state = test_state();
        let collector = SelfMetricsCollector::new(platform, state, None);

        let envelopes = collector.collect().await.unwrap();
        assert!(!envelopes.is_empty());

        let names: Vec<String> = envelopes
            .iter()
            .filter_map(|e| {
                MetricPayload::decode(e.payload.as_slice())
                    .ok()
                    .map(|p| p.name)
            })
            .collect();

        assert!(names.contains(&"agent.cpu.usage_percent".to_string()));
        assert!(names.contains(&"agent.memory.usage_bytes".to_string()));
        assert!(names.contains(&"agent.envelopes.sent_total".to_string()));
        assert!(names.contains(&"agent.buffer.used_bytes".to_string()));
        assert!(names.contains(&"agent.uptime_seconds".to_string()));
        assert!(names.contains(&"agent.redactions.total".to_string()));
    }

    #[test]
    fn parse_vm_rss_works() {
        let content = "VmPeak:\t  100000 kB\nVmRSS:\t   51200 kB\nVmSize:\t  200000 kB\n";
        let rss = SelfMetricsCollector::parse_vm_rss(content);
        assert_eq!(rss, Some(51200 * 1024));
    }

    #[test]
    fn parse_vm_rss_missing() {
        let content = "VmPeak:\t  100000 kB\n";
        let rss = SelfMetricsCollector::parse_vm_rss(content);
        assert_eq!(rss, None);
    }

    #[test]
    fn interval_is_30s() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let state = test_state();
        let collector = SelfMetricsCollector::new(platform, state, None);
        assert_eq!(collector.interval(), Duration::from_secs(30));
    }
}
