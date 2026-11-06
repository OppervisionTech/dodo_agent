//! Minimal HTTP health endpoint for liveness/readiness probes.
//!
//! `GET /healthz` answers 200 while the process is up. `GET /readyz` answers
//! 200 once startup finished (enrollment attempted, transport spawned) and 503
//! before that. Plain HTTP/1.1 over a tokio `TcpListener`, so it adds no
//! dependency (axum is only compiled with the `otel` feature).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Status line and body for a request line such as `GET /healthz HTTP/1.1`.
pub fn route(request_line: &str, ready: bool) -> (&'static str, &'static str) {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    match (method, path) {
        ("GET", "/healthz") => ("200 OK", "ok\n"),
        ("GET", "/readyz") if ready => ("200 OK", "ready\n"),
        ("GET", "/readyz") => ("503 Service Unavailable", "starting\n"),
        _ => ("404 Not Found", "not found\n"),
    }
}

/// Serve probes on `listen` until `token` is cancelled. A bind failure is
/// logged and the agent keeps running: health is an aid, not a dependency.
pub async fn serve(listen: String, ready: Arc<AtomicBool>, token: CancellationToken) {
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            warn!(listen = %listen, error = %e, "health server disabled: bind failed");
            return;
        }
    };
    info!(listen = %listen, "health server listening");

    loop {
        tokio::select! {
            _ = token.cancelled() => return,
            accepted = listener.accept() => {
                let Ok((mut stream, _)) = accepted else { continue };
                let ready = ready.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        stream.read(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) => n,
                        _ => return,
                    };
                    let head = String::from_utf8_lossy(&buf[..n]);
                    let first_line = head.lines().next().unwrap_or("");
                    let (status, body) = route(first_line, ready);
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_is_always_ok() {
        assert_eq!(route("GET /healthz HTTP/1.1", false).0, "200 OK");
        assert_eq!(route("GET /healthz HTTP/1.1", true).0, "200 OK");
    }

    #[test]
    fn readyz_follows_ready_flag() {
        assert_eq!(
            route("GET /readyz HTTP/1.1", false).0,
            "503 Service Unavailable"
        );
        assert_eq!(route("GET /readyz HTTP/1.1", true).0, "200 OK");
    }

    #[test]
    fn unknown_path_or_method_is_404() {
        assert_eq!(route("GET / HTTP/1.1", true).0, "404 Not Found");
        assert_eq!(route("POST /healthz HTTP/1.1", true).0, "404 Not Found");
        assert_eq!(route("", true).0, "404 Not Found");
    }

    #[tokio::test]
    async fn serves_probes_over_tcp() {
        let ready = Arc::new(AtomicBool::new(false));
        let token = CancellationToken::new();
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap().to_string();
        drop(probe);
        tokio::spawn(serve(addr.clone(), ready.clone(), token.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        async fn get(addr: &str, path: &str) -> String {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        }

        assert!(get(&addr, "/healthz").await.starts_with("HTTP/1.1 200"));
        assert!(get(&addr, "/readyz").await.starts_with("HTTP/1.1 503"));
        ready.store(true, Ordering::Relaxed);
        assert!(get(&addr, "/readyz").await.starts_with("HTTP/1.1 200"));
        token.cancel();
    }
}
