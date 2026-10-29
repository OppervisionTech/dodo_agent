pub mod buffer;
pub mod enrollment;
pub mod grpc_client;
pub mod proto;
pub mod retry;
pub mod tls;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("gRPC error: {code} - {message}")]
    Grpc { code: tonic::Code, message: String },
    #[error("timeout after {0}ms")]
    Timeout(u32),
    #[error("buffer error: {0}")]
    Buffer(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("retry exhausted after {attempts} attempts: {last_error}")]
    RetryExhausted { attempts: u32, last_error: String },
    #[error("not retryable: {0}")]
    NotRetryable(String),
}

pub type TransportResult<T> = Result<T, TransportError>;

/// Shared cell holding the current agent JWT (see `enrollment::refresh_token`).
/// Read before each gRPC call and swapped in place by the refresh task, so
/// every clone of a `TransportConfig` (e.g. the command channel's copy) sees
/// updates without needing its own refresh loop.
pub type SharedToken = std::sync::Arc<std::sync::RwLock<Option<String>>>;

/// Attaches auth metadata to an outgoing gRPC request: the agent JWT as
/// `authorization: Bearer <jwt>` plus `x-api-key`. The ingestor verifies the
/// signed JWT's agent/org/key binding and active API-key scope; both are required
/// by the matching validation-security deployment. Shared by `grpc_client` (unary calls)
/// and `agent-command`'s CommandStream (bidirectional) so both send the same
/// headers instead of drifting independently.
pub fn attach_auth_metadata<T>(request: &mut tonic::Request<T>, config: &TransportConfig) {
    if let Ok(guard) = config.agent_jwt.read() {
        if let Some(jwt) = guard.as_ref() {
            match tonic::metadata::MetadataValue::try_from(format!("Bearer {jwt}")) {
                Ok(val) => {
                    request.metadata_mut().insert("authorization", val);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to attach agent_jwt to gRPC metadata");
                }
            }
        }
    }

    if let Some(ref key) = config.api_key {
        if !key.is_empty() {
            match tonic::metadata::MetadataValue::try_from(key.as_str()) {
                Ok(val) => {
                    request.metadata_mut().insert("x-api-key", val);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to attach api_key to gRPC metadata");
                }
            }
        }
    }
}

/// Outcome of a batch submission.
#[derive(Debug, Clone)]
pub struct SubmitResult {
    pub accepted: u32,
    pub rejected: u32,
    pub errors: Vec<String>,
}

/// Configuration for transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub endpoint_address: String,
    pub timeout_ms: u32,
    pub retry_max: u32,
    pub retry_backoff_ms: u32,
    pub tls_enabled: bool,
    pub ca_cert_path: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    pub verify_server: bool,
    /// Active API key from dodo_portal sent as `x-api-key` gRPC metadata header.
    /// Required alongside the signed JWT by the ingestor's active key/org/scope
    /// checks. This is not a fallback that can bypass JWT verification.
    pub api_key: Option<String>,
    /// Short-lived signed identity bound to agent, organization and API key.
    /// The ingestor verifies its signature and claims. TLS/client certificates
    /// are configured separately; gateway mTLS enforcement requires deployment
    /// verification. `None` until successful enrollment or proof-based refresh.
    pub agent_jwt: SharedToken,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            endpoint_address: "localhost:443".to_string(),
            timeout_ms: 5000,
            retry_max: 3,
            retry_backoff_ms: 1000,
            tls_enabled: true,
            ca_cert_path: String::new(),
            client_cert_path: String::new(),
            client_key_path: String::new(),
            verify_server: true,
            api_key: None,
            agent_jwt: SharedToken::default(),
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/support/network.rs"]
mod test_network;

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn every_request_observes_the_current_identity_and_active_key() {
        let config = TransportConfig {
            api_key: Some("synthetic-key".into()),
            ..Default::default()
        };
        *config.agent_jwt.write().unwrap() = Some("first-token".into());
        let mut request = tonic::Request::new(());
        attach_auth_metadata(&mut request, &config);
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer first-token"
        );
        assert_eq!(
            request.metadata().get("x-api-key").unwrap(),
            "synthetic-key"
        );
        *config.agent_jwt.write().unwrap() = Some("refreshed-token".into());
        let mut request = tonic::Request::new(());
        attach_auth_metadata(&mut request, &config.clone());
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer refreshed-token"
        );
    }

    #[test]
    fn malformed_headers_cannot_inject_metadata() {
        let config = TransportConfig {
            api_key: Some("key\r\nx-other: injected".into()),
            ..Default::default()
        };
        *config.agent_jwt.write().unwrap() = Some("token\ninvalid".into());
        let mut request = tonic::Request::new(());
        attach_auth_metadata(&mut request, &config);
        assert!(request.metadata().is_empty());
        let mut config = config;
        config.api_key = Some(String::new());
        *config.agent_jwt.write().unwrap() = None;
        attach_auth_metadata(&mut request, &config);
        assert!(request.metadata().is_empty());
    }
}
