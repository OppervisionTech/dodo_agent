use crate::retry::{with_retry, RetryConfig};
use crate::{SubmitResult, TransportConfig, TransportResult};
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

        // Build protobuf batch request (simplified — in production this would use
        // the generated proto types from dodo_proto)
        let payload_bytes = Self::serialize_batch(&envelopes, agent_state);
        let payload_size = payload_bytes.len();

        let retry_config = RetryConfig {
            max_retries: self.config.retry_max,
            base_backoff_ms: self.config.retry_backoff_ms,
        };

        let result = with_retry(&retry_config, "submit_batch", || {
            let payload = payload_bytes.clone();
            let this = &self;
            async move {
                let channel = this.ensure_connected().await?;
                this.do_submit(channel, payload).await
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
                    payload_bytes = payload_size,
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
        _channel: tonic::transport::Channel,
        _payload: Vec<u8>,
    ) -> TransportResult<SubmitResult> {
        // In production, this calls IngestorServiceClient::submit_batch.
        // For now, we simulate the call structure:
        //
        // let mut client = IngestorServiceClient::new(channel);
        // let request = tonic::Request::new(SubmitBatchRequest { envelopes: ... });
        // let response = client.submit_batch(request).await?;

        // Placeholder: will be connected to actual proto client when integrating
        // with dodo_proto generated code
        Ok(SubmitResult {
            accepted: 0,
            rejected: 0,
            errors: vec!["not connected to real ingestor".to_string()],
        })
    }

    fn serialize_batch(envelopes: &[Envelope], _agent_state: &agent_core::AgentState) -> Vec<u8> {
        // Placeholder serialization — in production this builds proper protobuf
        // AgentEnvelope messages with all header fields populated from agent_state
        let mut buf = Vec::new();
        for env in envelopes {
            buf.extend_from_slice(&env.payload);
        }
        buf
    }

    /// Disconnect and clean up.
    pub async fn disconnect(&self) {
        let mut guard = self.channel.lock().await;
        *guard = None;
        info!("gRPC client disconnected");
    }
}
