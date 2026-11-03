use crate::proto::{self, IngestorServiceClient};
use crate::retry::{with_retry, RetryConfig};
use crate::{attach_auth_metadata, SubmitResult, TransportConfig, TransportError, TransportResult};
use agent_core::Envelope;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// gRPC client for submitting batches to the Ingestor via Kong.
pub struct GrpcClient {
    config: TransportConfig,
    channel: Arc<Mutex<Option<tonic::transport::Channel>>>,
}

impl GrpcClient {
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            channel: Arc::new(Mutex::new(None)),
        }
    }

    /// Ensure connection is established, reconnecting if needed.
    async fn ensure_connected(&self) -> TransportResult<tonic::transport::Channel> {
        let mut guard = self.channel.lock().await;
        if let Some(ref ch) = *guard {
            return Ok(ch.clone());
        }

        info!(
            endpoint = %self.config.endpoint_address,
            "connecting to ingestor via gRPC+mTLS"
        );

        let channel = crate::tls::build_grpc_channel(&self.config).await?;
        *guard = Some(channel.clone());
        Ok(channel)
    }

    /// Submit a batch of envelopes to the ingestor.
    pub async fn submit_batch(
        &self,
        envelopes: Vec<Envelope>,
        agent_state: &agent_core::AgentState,
    ) -> TransportResult<SubmitResult> {
        let batch_size = envelopes.len();
        let start = std::time::Instant::now();

        let proto_envelopes = Self::build_proto_envelopes(&envelopes, agent_state);

        let retry_config = RetryConfig {
            max_retries: self.config.retry_max,
            base_backoff_ms: self.config.retry_backoff_ms,
        };

        let result = with_retry(&retry_config, "submit_batch", || {
            let batch = proto_envelopes.clone();
            let this = &self;
            async move {
                let channel = this.ensure_connected().await?;
                this.do_submit(channel, batch).await
            }
        })
        .await;

        let elapsed = start.elapsed();
        match &result {
            Ok(r) => {
                info!(
                    batch_size = batch_size,
                    accepted = r.accepted,
                    rejected = r.rejected,
                    latency_ms = elapsed.as_millis() as u64,
                    "batch submitted successfully"
                );
            }
            Err(e) => {
                warn!(
                    batch_size = batch_size,
                    error = %e,
                    latency_ms = elapsed.as_millis() as u64,
                    "batch submission failed"
                );
                // Clear channel to force reconnect on next attempt
                let mut guard = self.channel.lock().await;
                *guard = None;
            }
        }

        result
    }

    async fn do_submit(
        &self,
        channel: tonic::transport::Channel,
        envelopes: Vec<proto::AgentEnvelope>,
    ) -> TransportResult<SubmitResult> {
        let count = envelopes.len();
        let mut client = IngestorServiceClient::new(channel);
        let mut request = tonic::Request::new(proto::SubmitBatchRequest { envelopes });

        attach_auth_metadata(&mut request, &self.config);

        let response = client
            .submit_batch(request)
            .await
            .map_err(|e| TransportError::Grpc {
                code: e.code(),
                message: e.message().to_string(),
            })?;
        let resp = response.into_inner();
        if u64::from(resp.accepted) + u64::from(resp.rejected) != count as u64 {
            return Err(TransportError::NotRetryable(
                "invalid upstream acknowledgement count".into(),
            ));
        }
        Ok(SubmitResult {
            accepted: resp.accepted,
            rejected: resp.rejected,
            errors: resp.errors,
        })
    }

    fn build_proto_envelopes(
        envelopes: &[Envelope],
        agent_state: &agent_core::AgentState,
    ) -> Vec<proto::AgentEnvelope> {
        envelopes
            .iter()
            .map(|env| proto::AgentEnvelope {
                agent_id: agent_state.agent_id.clone(),
                agent_version: agent_state.agent_version.clone(),
                agent_variant: agent_state.agent_variant.clone(),
                host_id: agent_state.host_id.clone(),
                hostname: agent_state.hostname.clone(),
                os_family: agent_state.os_family.clone(),
                cluster_id: String::new(),
                timestamp_unix_ns: env.timestamp_unix_ns,
                sequence_id: 0,
                signal_type: match env.signal_type {
                    agent_core::SignalType::Metric => proto::SignalType::Metric as i32,
                    agent_core::SignalType::Log => proto::SignalType::Log as i32,
                    agent_core::SignalType::Trace => proto::SignalType::Trace as i32,
                    agent_core::SignalType::Event => proto::SignalType::Event as i32,
                    agent_core::SignalType::Inventory => proto::SignalType::Inventory as i32,
                    agent_core::SignalType::Heartbeat => proto::SignalType::Heartbeat as i32,
                    agent_core::SignalType::SecurityEvent => {
                        proto::SignalType::SecurityEvent as i32
                    }
                    agent_core::SignalType::CustomEvent => proto::SignalType::CustomEvent as i32,
                },
                payload: env.payload.clone(),
                compression: proto::Compression::None as i32,
                buffered: env.buffered,
                retry_count: env.retry_count,
            })
            .collect()
    }

    /// Disconnect and clean up.
    pub async fn disconnect(&self) {
        let mut guard = self.channel.lock().await;
        *guard = None;
        info!("gRPC client disconnected");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn state() -> agent_core::AgentState {
        agent_core::AgentState::new(
            "agent".into(),
            "version".into(),
            "linux".into(),
            "hostname".into(),
            "host-id".into(),
            "linux".into(),
        )
    }
    fn envelopes() -> Vec<Envelope> {
        [
            agent_core::SignalType::Metric,
            agent_core::SignalType::Log,
            agent_core::SignalType::Trace,
            agent_core::SignalType::Event,
            agent_core::SignalType::Inventory,
            agent_core::SignalType::Heartbeat,
            agent_core::SignalType::SecurityEvent,
            agent_core::SignalType::CustomEvent,
        ]
        .into_iter()
        .map(|signal_type| Envelope {
            signal_type,
            payload: vec![42],
            timestamp_unix_ns: 123,
            buffered: true,
            retry_count: 2,
        })
        .collect()
    }

    #[test]
    fn wire_envelopes_carry_only_enrolled_identity_and_canonical_compression() {
        let messages = GrpcClient::build_proto_envelopes(&envelopes(), &state());
        for (index, message) in messages.iter().enumerate() {
            assert_eq!(message.signal_type, index as i32 + 1);
            assert_eq!(message.compression, 1);
            assert_eq!(message.agent_id, "agent");
            assert_eq!(message.host_id, "host-id");
            assert_eq!(message.hostname, "hostname");
            assert_eq!(message.agent_version, "version");
            assert_eq!(message.agent_variant, "linux");
            assert_eq!(message.os_family, "linux");
            assert_eq!(message.timestamp_unix_ns, 123);
            assert_eq!(message.payload, vec![42]);
            assert!(message.buffered);
            assert_eq!(message.retry_count, 2);
        }
    }

    #[tokio::test]
    async fn actual_grpc_retries_unavailable_and_reuses_connection_with_auth() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let server = crate::test_network::grpc(move |request| {
            assert_eq!(
                request.uri().path(),
                "/dodo.proto.v1.IngestorService/SubmitBatch"
            );
            assert_eq!(request.headers()["authorization"], "Bearer synthetic-jwt");
            assert_eq!(request.headers()["x-api-key"], "synthetic-key");
            let batch = proto::SubmitBatchRequest::decode(&request.body()[5..]).unwrap();
            assert_eq!(batch.envelopes[0].agent_id, "agent");
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                return (14, vec![]);
            }
            (
                0,
                proto::SubmitBatchResponse {
                    accepted: batch.envelopes.len() as u32,
                    rejected: 0,
                    errors: vec![],
                }
                .encode_to_vec(),
            )
        })
        .await;
        let config = TransportConfig {
            endpoint_address: server.address.clone(),
            tls_enabled: false,
            timeout_ms: 1000,
            retry_max: 1,
            retry_backoff_ms: 1,
            api_key: Some("synthetic-key".into()),
            ..Default::default()
        };
        *config.agent_jwt.write().unwrap() = Some("synthetic-jwt".into());
        let client = GrpcClient::new(config);
        assert_eq!(
            client
                .submit_batch(envelopes(), &state())
                .await
                .unwrap()
                .accepted,
            8
        );
        assert_eq!(
            client
                .submit_batch(envelopes(), &state())
                .await
                .unwrap()
                .accepted,
            8
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        client.disconnect().await;
        assert!(client.channel.lock().await.is_none());
    }

    #[tokio::test]
    async fn partial_and_invalid_acknowledgements_never_duplicate_accepted_data() {
        for invalid in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let server = crate::test_network::grpc(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                (
                    0,
                    proto::SubmitBatchResponse {
                        accepted: 3,
                        rejected: if invalid { 0 } else { 5 },
                        errors: vec!["explicit upstream rejection".into()],
                    }
                    .encode_to_vec(),
                )
            })
            .await;
            let client = GrpcClient::new(TransportConfig {
                endpoint_address: server.address.clone(),
                tls_enabled: false,
                retry_max: 3,
                retry_backoff_ms: 1,
                ..Default::default()
            });
            let result = client.submit_batch(envelopes(), &state()).await;
            if invalid {
                assert!(matches!(result, Err(TransportError::NotRetryable(_))));
                assert!(client.channel.lock().await.is_none());
            } else {
                let result = result.unwrap();
                assert_eq!((result.accepted, result.rejected), (3, 5));
                assert_eq!(result.errors, ["explicit upstream rejection"]);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}
