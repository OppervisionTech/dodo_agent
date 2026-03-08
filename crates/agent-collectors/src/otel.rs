//! OpenTelemetry passthrough collector — HU027.
//!
//! This collector is special: rather than polling, it listens on
//! localhost:4317 (gRPC) and localhost:4318 (HTTP) for incoming OTLP data.
//!
//! # Full implementation plan (post-MVP)
//!
//! 1. **gRPC listener (localhost:4317)**:
//!    - Use `tonic` to implement the OTLP gRPC ExportTraceServiceRequest,
//!      ExportMetricsServiceRequest, and ExportLogsServiceRequest endpoints.
//!    - Bind to 127.0.0.1 ONLY (NEVER 0.0.0.0) to prevent external access.
//!    - Convert received OTLP protobuf messages into `Envelope` instances
//!      with appropriate SignalType (Trace, Metric, Log).
//!    - The raw OTLP protobuf bytes become the Envelope payload — no
//!      re-serialization needed, just wrap and forward.
//!
//! 2. **HTTP listener (localhost:4318)**:
//!    - Use `axum` or `hyper` to accept OTLP/HTTP POST requests at:
//!      - `/v1/traces`
//!      - `/v1/metrics`
//!      - `/v1/logs`
//!    - Accept both protobuf and JSON content types.
//!    - Convert to Envelope and forward.
//!
//! 3. **SDK integration (localhost:4317/4318)**:
//!    - The same endpoints serve both OTEL-native applications and
//!      DoDo SDK instrumented applications.
//!    - SDK sends custom events via a DoDo-specific OTLP extension
//!      or a separate gRPC service on the same port.
//!
//! 4. **Rate limiting**:
//!    - Per-client rate limiting based on source PID or connection.
//!    - Global rate limit to prevent agent overload.
//!
//! 5. **Lifecycle**:
//!    - Listeners start in `new()` or via a separate `start()` method.
//!    - The `collect()` method drains the internal buffer of received
//!      envelopes since the last tick.
//!    - Graceful shutdown stops accepting new connections and drains.
//!
//! # SECURITY
//! - MUST bind to 127.0.0.1 only, NEVER 0.0.0.0
//! - Agent NEVER listens on external network interfaces
//! - This is the ONLY network-facing component of the agent
//!   (aside from outbound gRPC to Kong)

use std::sync::Arc;
use std::time::Duration;

use agent_core::{Collector, CollectorError, Envelope, SignalType};
use agent_platform::Platform;

/// gRPC listen address — MUST be localhost only.
#[allow(dead_code)]
const GRPC_LISTEN_ADDR: &str = "127.0.0.1:4317";

/// HTTP listen address — MUST be localhost only.
#[allow(dead_code)]
const HTTP_LISTEN_ADDR: &str = "127.0.0.1:4318";

/// OpenTelemetry passthrough collector (MVP stub).
///
/// In the full implementation this will run gRPC and HTTP listeners
/// on localhost. For MVP, it returns empty results from `collect()`.
pub struct OtelCollector {
    #[allow(dead_code)]
    platform: Arc<dyn Platform>,
}

impl OtelCollector {
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        tracing::info!(
            grpc_addr = GRPC_LISTEN_ADDR,
            http_addr = HTTP_LISTEN_ADDR,
            "OTEL collector initialized (MVP stub — listeners not started)"
        );
        Self { platform }
    }
}

impl Collector for OtelCollector {
    fn name(&self) -> &str {
        "otel"
    }

    fn signal_type(&self) -> SignalType {
        // OTEL can produce traces, metrics, and logs. We report Trace as
        // the primary type; individual envelopes carry their own SignalType.
        SignalType::Trace
    }

    fn interval(&self) -> Duration {
        // In the full implementation the collect() call drains a buffer
        // that is filled asynchronously by the gRPC/HTTP listeners.
        // We poll at 1 second to check for buffered data.
        Duration::from_secs(1)
    }

    fn collect(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>,
    > {
        Box::pin(async move {
            // MVP stub: no listeners running, always return empty.
            // Post-MVP: drain the internal receive buffer here.
            Ok(Vec::new())
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
    async fn stub_returns_empty() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = OtelCollector::new(platform);

        let envelopes = collector.collect().await.unwrap();
        assert!(envelopes.is_empty());
    }

    #[test]
    fn listen_addresses_are_localhost() {
        assert!(GRPC_LISTEN_ADDR.starts_with("127.0.0.1"));
        assert!(HTTP_LISTEN_ADDR.starts_with("127.0.0.1"));
    }

    #[test]
    fn name_is_otel() {
        let platform = Arc::new(MockPlatform::new()) as Arc<dyn Platform>;
        let collector = OtelCollector::new(platform);
        assert_eq!(collector.name(), "otel");
    }
}
