//! Disk collector — HU021.
//!
//! Collects disk space usage per mount point and disk I/O metrics per
//! device at 10-second intervals. I/O metrics are computed as deltas
//! between consecutive samples.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::{DiskIo, Platform};
use tokio::sync::Mutex;

use crate::helpers::metric_envelope;

/// Collects disk space and I/O metrics from the platform.
pub struct DiskCollector {
    platform: Arc<dyn Platform>,
    /// Previous I/O counters keyed by device name, for delta calculation.
    previous_io: Mutex<HashMap<String, DiskIo>>,
}

impl DiskCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Self {
            platform,
            previous_io: Mutex::new(HashMap::new()),
        }
    }
}

impl Collector for DiskCollector {
    fn name(&self) -> &str {
        "disk"
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

            // ------------------------------------------------------------------
            // Disk space per mount point
            // ------------------------------------------------------------------
            match self.platform.disk_spaces() {
                Ok(spaces) => {
                    for ds in &spaces {
                        let labels: [(&str, &str); 3] = [
                            ("mount_point", &ds.mount_point),
                            ("device", &ds.device),
                            ("filesystem", &ds.filesystem),
                        ];

                        envelopes.push(metric_envelope(
                            "disk.space.total.bytes",
                            ds.total_bytes as f64,
                            &labels,
                            "gauge",
                        ));
                        envelopes.push(metric_envelope(
                            "disk.space.used.bytes",
                            ds.used_bytes as f64,
                            &labels,
                            "gauge",
                        ));
                        envelopes.push(metric_envelope(
                            "disk.space.free.bytes",
                            ds.free_bytes as f64,
                            &labels,
                            "gauge",
                        ));

                        let usage_pct = if ds.total_bytes > 0 {
                            (ds.used_bytes as f64 / ds.total_bytes as f64) * 100.0
                        } else {
                            0.0
                        };
                        envelopes.push(metric_envelope(
                            "disk.space.usage.percent",
                            usage_pct,
                            &labels,
                            "gauge",
                        ));

                        // Inode metrics
                        envelopes.push(metric_envelope(
                            "disk.inodes.total",
                            ds.inodes_total as f64,
                            &labels,
                            "gauge",
                        ));
                        envelopes.push(metric_envelope(
                            "disk.inodes.used",
                            ds.inodes_used as f64,
                            &labels,
                            "gauge",
                        ));

                        let inode_pct = if ds.inodes_total > 0 {
                            (ds.inodes_used as f64 / ds.inodes_total as f64) * 100.0
                        } else {
                            0.0
                        };
                        envelopes.push(metric_envelope(
                            "disk.inodes.usage.percent",
                            inode_pct,
                            &labels,
                            "gauge",
                        ));
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read disk spaces");
                }
            }

            // ------------------------------------------------------------------
            // Disk I/O per device (delta computation)
            // ------------------------------------------------------------------
            match self.platform.disk_io() {
                Ok(current_ios) => {
                    let mut prev_guard = self.previous_io.lock().await;

                    for io in &current_ios {
                        let device_label: [(&str, &str); 1] = [("device", &io.device)];

                        if let Some(prev) = prev_guard.get(&io.device) {
                            let read_bytes_delta = io.read_bytes.saturating_sub(prev.read_bytes);
                            let write_bytes_delta = io.write_bytes.saturating_sub(prev.write_bytes);
                            let read_ops_delta = io.read_ops.saturating_sub(prev.read_ops);
                            let write_ops_delta = io.write_ops.saturating_sub(prev.write_ops);
                            let io_time_delta = io.io_time_ms.saturating_sub(prev.io_time_ms);
                            let weighted_io_delta = io
                                .weighted_io_time_ms
                                .saturating_sub(prev.weighted_io_time_ms);

                            envelopes.push(metric_envelope(
                                "disk.io.read.bytes",
                                read_bytes_delta as f64,
                                &device_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "disk.io.write.bytes",
                                write_bytes_delta as f64,
                                &device_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "disk.io.read.ops",
                                read_ops_delta as f64,
                                &device_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "disk.io.write.ops",
                                write_ops_delta as f64,
                                &device_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "disk.io.time_ms",
                                io_time_delta as f64,
                                &device_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "disk.io.weighted_time_ms",
                                weighted_io_delta as f64,
                                &device_label,
                                "counter",
                            ));

                            // I/O utilization approximation: io_time_delta / interval_ms
                            // interval is 10s = 10_000 ms
                            let util_pct = (io_time_delta as f64 / 10_000.0) * 100.0;
                            envelopes.push(metric_envelope(
                                "disk.io.utilization.percent",
                                util_pct.min(100.0),
                                &device_label,
                                "gauge",
                            ));
                        } else {
                            tracing::debug!(
                                device = %io.device,
                                "disk I/O: first sample, deltas available next tick"
                            );
                        }
                    }

                    // Update previous snapshot
                    prev_guard.clear();
                    for io in current_ios {
                        prev_guard.insert(io.device.clone(), io);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read disk I/O counters");
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
    async fn collects_disk_space_metrics() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = DiskCollector::new(platform);

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

        assert!(names.contains(&"disk.space.total.bytes".to_string()));
        assert!(names.contains(&"disk.space.used.bytes".to_string()));
        assert!(names.contains(&"disk.space.usage.percent".to_string()));
    }

    #[tokio::test]
    async fn second_collection_has_io_deltas() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = DiskCollector::new(platform);

        // First tick: captures baseline
        let _ = collector.collect().await;
        // Second tick: should produce I/O deltas
        let envelopes = collector.collect().await.unwrap();

        let names: Vec<String> = envelopes
            .iter()
            .filter_map(|e| {
                let v: serde_json::Value = serde_json::from_slice(&e.payload).ok()?;
                v["name"].as_str().map(|s| s.to_string())
            })
            .collect();

        // MockPlatform returns same values, so deltas will be 0, but metrics should still exist
        assert!(names.contains(&"disk.io.read.bytes".to_string()));
        assert!(names.contains(&"disk.io.write.bytes".to_string()));
    }
}
