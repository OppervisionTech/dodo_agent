//! Heartbeat collector — HU031.
//!
//! Sends periodic heartbeat signals so the health monitor on the backend
//! knows this agent is alive. The heartbeat carries agent identity,
//! version, uptime, and a summary of active collectors.
//!
//! Default interval: 30 seconds. The health monitor expects a heartbeat
//! at least every 90 seconds (3x TTL) before marking the agent as stale.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use agent_core::{AgentState, Collector, CollectorError, Envelope, SignalType};

use crate::helpers::heartbeat_envelope;

/// Sends periodic heartbeat envelopes with agent identity and status.
pub struct HeartbeatCollector {
    state: Arc<AgentState>,
}

impl HeartbeatCollector {
    pub fn new(state: Arc<AgentState>) -> Self {
        Self { state }
    }
}

impl Collector for HeartbeatCollector {
    fn name(&self) -> &str {
        "heartbeat"
    }

    fn signal_type(&self) -> SignalType {
        SignalType::Heartbeat
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
            let active_collectors = {
                let guard = self
                    .state
                    .active_collectors
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                guard.clone()
            };

            let config_hash = {
                let guard = self
                    .state
                    .config_hash
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                guard.clone()
            };

            let envelope = heartbeat_envelope(serde_json::json!({
                "agent_id": self.state.agent_id,
                "agent_version": self.state.agent_version,
                "agent_variant": self.state.agent_variant,
                "hostname": self.state.hostname,
                "host_id": self.state.host_id,
                "os_family": self.state.os_family,
                "uptime_seconds": self.state.uptime_seconds(),
                "envelopes_sent": self.state.envelopes_sent.load(Ordering::Relaxed),
                "envelopes_failed": self.state.envelopes_failed.load(Ordering::Relaxed),
                "buffer_used_bytes": self.state.buffer_used_bytes.load(Ordering::Relaxed),
                "active_collectors": active_collectors,
                "config_hash": config_hash,
            }));

            Ok(vec![envelope])
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::HeartbeatPayload;
    use prost::Message;

    fn test_state() -> Arc<AgentState> {
        Arc::new(AgentState::new(
            "test-agent-id".into(),
            "0.1.0".into(),
            "linux".into(),
            "test-host".into(),
            "test-host-id".into(),
            "linux".into(),
        ))
    }

    #[tokio::test]
    async fn produces_one_heartbeat_envelope() {
        let state = test_state();
        let collector = HeartbeatCollector::new(state);

        let envelopes = collector.collect().await.unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].signal_type, SignalType::Heartbeat);
    }

    #[tokio::test]
    async fn heartbeat_contains_agent_version() {
        let state = test_state();
        let collector = HeartbeatCollector::new(state);

        let envelopes = collector.collect().await.unwrap();
        let payload = HeartbeatPayload::decode(envelopes[0].payload.as_slice()).unwrap();
        assert_eq!(payload.agent_version, "0.1.0");
    }

    #[test]
    fn interval_is_30s() {
        let state = test_state();
        let collector = HeartbeatCollector::new(state);
        assert_eq!(collector.interval(), Duration::from_secs(30));
    }

    #[test]
    fn name_is_heartbeat() {
        let state = test_state();
        let collector = HeartbeatCollector::new(state);
        assert_eq!(collector.name(), "heartbeat");
    }
}
