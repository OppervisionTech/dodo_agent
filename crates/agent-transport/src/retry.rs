use crate::{SubmitResult, TransportError, TransportResult};
use tracing::{debug, warn};

/// gRPC statuses that are retryable.
///
/// tonic reports its own client-side request timeout as `Cancelled` with the
/// message "Timeout expired", not as `DeadlineExceeded`. Treat that as the
/// deadline it is; any other `Cancelled` (e.g. shutdown) is not retried.
fn is_retryable(code: tonic::Code, message: &str) -> bool {
    match code {
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => true,
        tonic::Code::Cancelled => message.contains("Timeout expired"),
        _ => false,
    }
}

/// gRPC status codes that must NOT be retried.
fn is_non_retryable_code(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::InvalidArgument
            | tonic::Code::Unauthenticated
            | tonic::Code::ResourceExhausted
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
            Err(TransportError::Grpc { code, ref message }) => {
                if is_non_retryable_code(code) {
                    return Err(TransportError::NotRetryable(format!(
                        "{operation_name}: {code} - {message}"
                    )));
                }
                if !is_retryable(code, message) || attempt >= config.max_retries {
                    last_error = format!("{code} - {message}");
                    break;
                }
                let backoff_ms = config.base_backoff_ms * 2u32.pow(attempt);
                warn!(
                    operation = operation_name,
                    code = ?code,
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
            Err(e @ TransportError::NotRetryable(_)) => return Err(e),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn retry_policy_distinguishes_transient_permanent_and_bounded_failures() {
        let defaults = RetryConfig::default();
        assert_eq!((defaults.max_retries, defaults.base_backoff_ms), (3, 1000));
        for (code, expected_calls) in [
            (tonic::Code::InvalidArgument, 1),
            (tonic::Code::Unauthenticated, 1),
            (tonic::Code::ResourceExhausted, 1),
            (tonic::Code::PermissionDenied, 1),
            (tonic::Code::Unavailable, 3),
            (tonic::Code::DeadlineExceeded, 3),
            (tonic::Code::Cancelled, 1),
        ] {
            let calls = AtomicUsize::new(0);
            let result = with_retry(
                &RetryConfig {
                    max_retries: 2,
                    base_backoff_ms: 1,
                },
                "contract",
                || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    std::future::ready(Err(TransportError::Grpc {
                        code,
                        message: "synthetic".into(),
                    }))
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::Relaxed), expected_calls);
        }
        // tonic's client timeout surfaces as Cancelled("Timeout expired").
        let calls = AtomicUsize::new(0);
        let result = with_retry(
            &RetryConfig {
                max_retries: 2,
                base_backoff_ms: 1,
            },
            "contract",
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                std::future::ready(Err(TransportError::Grpc {
                    code: tonic::Code::Cancelled,
                    message: "Timeout expired".into(),
                }))
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(TransportError::RetryExhausted { attempts: 3, .. })
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        for timeout in [false, true] {
            let calls = AtomicUsize::new(0);
            let result = with_retry(
                &RetryConfig {
                    max_retries: 1,
                    base_backoff_ms: 1,
                },
                "contract",
                || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    std::future::ready(Err(if timeout {
                        TransportError::Timeout(10)
                    } else {
                        TransportError::Connection("offline".into())
                    }))
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(TransportError::RetryExhausted { attempts: 2, .. })
            ));
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }
}
