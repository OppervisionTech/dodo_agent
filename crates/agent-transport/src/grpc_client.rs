use crate::proto::{self, IngestorServiceClient};
use crate::retry::{with_retry, RetryConfig};
use crate::{SubmitResult, TransportConfig, TransportError, TransportResult};
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
        let mut client = IngestorServiceClient::new(channel);
        let request = tonic::Request::new(proto::SubmitBatchRequest { envelopes });
        let response = client.submit_batch(request).await.map_err(|e| {
            TransportError::Grpc {
                code: e.code().to_string(),
                message: e.message().to_string(),
            }
        })?;
        let resp = response.into_inner();
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
                    agent_core::SignalType::SecurityEvent => proto::SignalType::SecurityEvent as i32,
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
