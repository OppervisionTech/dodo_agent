pub mod buffer;
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
    Grpc { code: String, message: String },
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
        }
    }
}
