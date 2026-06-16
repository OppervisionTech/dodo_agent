//! Network collector — HU022.
//!
//! Collects network interface counters (bytes, packets, errors, drops) as
//! deltas between consecutive samples, plus TCP connection state counts.
//! Interval: 5 seconds.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::{NetworkCounters, Platform};
use tokio::sync::Mutex;

use crate::helpers::metric_envelope;

/// Collects network interface and TCP connection metrics.
pub struct NetworkCollector {
    platform: Arc<dyn Platform>,
    /// Previous network counters keyed by interface name, for delta calculation.
    previous: Mutex<HashMap<String, NetworkCounters>>,
}

impl NetworkCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Self {
            platform,
            previous: Mutex::new(HashMap::new()),
        }
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &str {
        "network"
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
            // Network interface counters (delta computation)
            // ------------------------------------------------------------------
            match self.platform.network_counters() {
                Ok(current_counters) => {
                    let mut prev_guard = self.previous.lock().await;

                    for nc in &current_counters {
                        let iface_label: [(&str, &str); 1] = [("interface", &nc.interface)];

                        if let Some(prev) = prev_guard.get(&nc.interface) {
                            envelopes.push(metric_envelope(
                                "network.bytes.recv",
                                nc.bytes_recv.saturating_sub(prev.bytes_recv) as f64,
                                &iface_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "network.bytes.sent",
                                nc.bytes_sent.saturating_sub(prev.bytes_sent) as f64,
                                &iface_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "network.packets.recv",
                                nc.packets_recv.saturating_sub(prev.packets_recv) as f64,
                                &iface_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "network.packets.sent",
                                nc.packets_sent.saturating_sub(prev.packets_sent) as f64,
                                &iface_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "network.errors.recv",
                                nc.errors_recv.saturating_sub(prev.errors_recv) as f64,
                                &iface_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "network.errors.sent",
                                nc.errors_sent.saturating_sub(prev.errors_sent) as f64,
                                &iface_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "network.drops.recv",
                                nc.drops_recv.saturating_sub(prev.drops_recv) as f64,
                                &iface_label,
                                "counter",
                            ));
                            envelopes.push(metric_envelope(
                                "network.drops.sent",
                                nc.drops_sent.saturating_sub(prev.drops_sent) as f64,
                                &iface_label,
                                "counter",
                            ));
                        } else {
                            tracing::debug!(
                                interface = %nc.interface,
                                "network: first sample, deltas available next tick"
                            );
                        }
                    }

                    // Update previous snapshot
                    prev_guard.clear();
                    for nc in current_counters {
                        prev_guard.insert(nc.interface.clone(), nc);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read network counters");
                }
            }

            // ------------------------------------------------------------------
            // TCP connection state counts
            // ------------------------------------------------------------------
            match self.platform.tcp_connections() {
                Ok(tcp) => {
                    envelopes.push(metric_envelope(
                        "network.tcp.established",
                        tcp.established as f64,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "network.tcp.time_wait",
                        tcp.time_wait as f64,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "network.tcp.close_wait",
                        tcp.close_wait as f64,
                        &[],
                        "gauge",
                    ));
                    envelopes.push(metric_envelope(
                        "network.tcp.total",
                        tcp.total as f64,
                        &[],
                        "gauge",
                    ));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read TCP connections");
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
    use crate::helpers::MetricPayload;
    use agent_platform::common::MockPlatform;
    use prost::Message;

    fn metric_names(envelopes: &[Envelope]) -> Vec<String> {
        envelopes
            .iter()
            .filter_map(|e| {
                MetricPayload::decode(e.payload.as_slice())
                    .ok()
                    .map(|p| p.name)
            })
            .collect()
    }

    #[tokio::test]
    async fn first_collection_has_tcp_metrics() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = NetworkCollector::new(platform);

        let envelopes = collector.collect().await.unwrap();
        let names = metric_names(&envelopes);
        assert!(names.contains(&"network.tcp.established".to_string()));
        assert!(names.contains(&"network.tcp.total".to_string()));
    }

    #[tokio::test]
    async fn second_collection_has_interface_deltas() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = NetworkCollector::new(platform);

        let _ = collector.collect().await;
        let envelopes = collector.collect().await.unwrap();
        let names = metric_names(&envelopes);
        assert!(names.contains(&"network.bytes.recv".to_string()));
        assert!(names.contains(&"network.bytes.sent".to_string()));
    }
}
