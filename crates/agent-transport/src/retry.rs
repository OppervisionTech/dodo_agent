use crate::{SubmitResult, TransportError, TransportResult};
use tracing::{debug, warn};

/// gRPC status codes that are retryable.
fn is_retryable_code(code: &str) -> bool {
    matches!(code, "UNAVAILABLE" | "DEADLINE_EXCEEDED")
}

/// gRPC status codes that must NOT be retried.
fn is_non_retryable_code(code: &str) -> bool {
    matches!(
        code,
        "INVALID_ARGUMENT" | "UNAUTHENTICATED" | "RESOURCE_EXHAUSTED"
    )
}

/// Retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_backoff_ms: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_backoff_ms: 1000,
        }
    }
}

/// Execute an async operation with exponential backoff retry.
pub async fn with_retry<F, Fut>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> TransportResult<SubmitResult>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = TransportResult<SubmitResult>>,
{
    let mut attempt = 0u32;
    let last_error;

    loop {
        match operation().await {
            Ok(result) => {
                if attempt > 0 {
                    debug!(
                        operation = operation_name,
                        attempt = attempt + 1,
                        "succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(TransportError::Grpc {
                ref code,
                ref message,
            }) => {
                if is_non_retryable_code(code) {
                    return Err(TransportError::NotRetryable(format!(
                        "{operation_name}: {code} - {message}"
                    )));
                }
                if !is_retryable_code(code) || attempt >= config.max_retries {
                    last_error = format!("{code} - {message}");
                    break;
                }
                let backoff_ms = config.base_backoff_ms * 2u32.pow(attempt);
                warn!(
                    operation = operation_name,
                    code = code,
                    attempt = attempt + 1,
                    max = config.max_retries,
                    backoff_ms = backoff_ms,
                    "retrying after transient error"
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms as u64)).await;
                attempt += 1;
            }
            Err(TransportError::Timeout(ms)) => {
                if attempt >= config.max_retries {
                    last_error = format!("timeout after {ms}ms");
                    break;
                }
                let backoff_ms = config.base_backoff_ms * 2u32.pow(attempt);
                warn!(
                    operation = operation_name,
                    attempt = attempt + 1,
                    max = config.max_retries,
                    backoff_ms = backoff_ms,
                    "retrying after timeout"
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms as u64)).await;
                attempt += 1;
            }
            Err(e) => {
                if attempt >= config.max_retries {
                    last_error = e.to_string();
                    break;
                }
                let backoff_ms = config.base_backoff_ms * 2u32.pow(attempt);
                warn!(
                    operation = operation_name,
                    error = %e,
                    attempt = attempt + 1,
                    max = config.max_retries,
                    backoff_ms = backoff_ms,
                    "retrying after error"
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms as u64)).await;
                attempt += 1;
            }
        }
    }

    Err(TransportError::RetryExhausted {
        attempts: attempt + 1,
        last_error,
    })
}
