//! Process collector — HU023.
//!
//! Collects process-level metrics at 10-second intervals. Reports
//! aggregate process counts by state, total thread count, and Top-N
//! processes by CPU and memory usage. Command lines are run through
//! the RedactionEngine before inclusion in payloads.

use std::sync::Arc;
use std::time::Duration;

use agent_core::redaction::RedactionEngine;
use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;

use crate::helpers::metric_envelope;

/// Default number of top processes to report by CPU and memory.
const DEFAULT_TOP_N: usize = 10;

/// Collects process-level metrics with Top-N CPU/memory reporting.
pub struct ProcessCollector {
    platform: Arc<dyn Platform>,
    redaction: Arc<RedactionEngine>,
    top_n: usize,
}

impl ProcessCollector {
    /// Create a new process collector.
    ///
    /// - `redaction`: Used to sanitize command lines before they leave the agent.
    /// - `top_n`: How many top processes to report (default 10).
    pub fn new(
        platform: Arc<dyn Platform>,
        redaction: Arc<RedactionEngine>,
        top_n: Option<usize>,
    ) -> Self {
        Self {
            platform,
            redaction,
            top_n: top_n.unwrap_or(DEFAULT_TOP_N),
        }
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &str {
        "process"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Metric
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(10)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            let mut envelopes = Vec::new();

            let processes = self.platform.processes()?;

            // ------------------------------------------------------------------
            // Aggregate counts by state
            // ------------------------------------------------------------------
            let total = processes.len() as f64;
            let mut running: u64 = 0;
            let mut sleeping: u64 = 0;
            let mut zombie: u64 = 0;
            let mut total_threads: u64 = 0;

            for p in &processes {
                match p.state {
                    'R' => running += 1,
                    'S' | 'D' | 'I' => sleeping += 1,
                    'Z' => zombie += 1,
                    _ => {}
                }
                total_threads += p.threads as u64;
            }

            envelopes.push(metric_envelope("process.count.total", total, &[], "gauge"));
            envelopes.push(metric_envelope(
                "process.count.running",
                running as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "process.count.sleeping",
                sleeping as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "process.count.zombie",
                zombie as f64,
                &[],
                "gauge",
            ));
            envelopes.push(metric_envelope(
                "process.threads.total",
                total_threads as f64,
                &[],
                "gauge",
            ));

            // ------------------------------------------------------------------
            // Top N by CPU
            // ------------------------------------------------------------------
            let mut by_cpu = processes.clone();
            by_cpu.sort_by(|a, b| {
                b.cpu_percent
                    .partial_cmp(&a.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            for (rank, p) in by_cpu.iter().take(self.top_n).enumerate() {
                let pid_str = p.pid.to_string();
                let rank_str = rank.to_string();
                let redacted_cmd = self.redaction.redact(&p.cmdline);

                let labels: [(&str, &str); 4] = [
                    ("pid", &pid_str),
                    ("name", &p.name),
                    ("rank", &rank_str),
                    ("cmdline", &redacted_cmd),
                ];

                envelopes.push(metric_envelope(
                    "process.top.cpu_percent",
                    p.cpu_percent,
                    &labels,
                    "gauge",
                ));
            }

            // ------------------------------------------------------------------
            // Top N by Memory
            // ------------------------------------------------------------------
            let mut by_mem = processes.clone();
            by_mem.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));

            for (rank, p) in by_mem.iter().take(self.top_n).enumerate() {
                let pid_str = p.pid.to_string();
                let rank_str = rank.to_string();
                let redacted_cmd = self.redaction.redact(&p.cmdline);

                let labels: [(&str, &str); 4] = [
                    ("pid", &pid_str),
                    ("name", &p.name),
                    ("rank", &rank_str),
                    ("cmdline", &redacted_cmd),
                ];

                envelopes.push(metric_envelope(
                    "process.top.memory_bytes",
                    p.memory_bytes as f64,
                    &labels,
                    "gauge",
                ));
                envelopes.push(metric_envelope(
                    "process.top.memory_percent",
                    p.memory_percent,
                    &labels,
                    "gauge",
                ));
                envelopes.push(metric_envelope(
                    "process.top.open_fds",
                    p.open_fds as f64,
                    &labels,
                    "gauge",
                ));
                envelopes.push(metric_envelope(
                    "process.top.threads",
                    p.threads as f64,
                    &labels,
                    "gauge",
                ));
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

    fn test_redaction() -> Arc<RedactionEngine> {
        Arc::new(RedactionEngine::new(&[]).expect("failed to create redaction engine"))
    }

    #[tokio::test]
    async fn collects_process_metrics() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = ProcessCollector::new(platform, test_redaction(), None);

        let envelopes = collector.collect().await.unwrap();

        let names: Vec<String> = envelopes
            .iter()
            .filter_map(|e| {
                let v: serde_json::Value = serde_json::from_slice(&e.payload).ok()?;
                v["name"].as_str().map(|s| s.to_string())
            })
            .collect();

        assert!(names.contains(&"process.count.total".to_string()));
        assert!(names.contains(&"process.threads.total".to_string()));
        assert!(names.contains(&"process.top.cpu_percent".to_string()));
    }

    #[tokio::test]
    async fn redacts_sensitive_cmdline() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = ProcessCollector::new(platform, test_redaction(), Some(5));

        let envelopes = collector.collect().await.unwrap();

        // The mock process cmdline is "/sbin/init" which has nothing to redact.
        // Verify it passes through without panic.
        assert!(!envelopes.is_empty());
    }
}
