//! Signal handling — graceful shutdown via OS signals.
//!
//! Part of HU034 (signal handling). Listens for SIGTERM, SIGINT (Unix)
//! and Ctrl+C (all platforms). Returns a `ShutdownReason` so the caller
//! can distinguish config-reload requests (SIGHUP) from actual shutdown.

/// Why the agent is shutting down (or reloading).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SIGTERM received — graceful shutdown requested by init/systemd.
    Sigterm,

    /// SIGINT / Ctrl+C received — operator requested shutdown.
    Sigint,

    /// SIGHUP received — convention for config reload (Unix only).
    /// The caller should reload configuration and NOT terminate.
    Sighup,
}

impl std::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownReason::Sigterm => f.write_str("SIGTERM"),
            ShutdownReason::Sigint => f.write_str("SIGINT"),
            ShutdownReason::Sighup => f.write_str("SIGHUP"),
        }
    }
}

/// Wait for an OS shutdown/reload signal.
///
/// On Unix, listens for SIGTERM, SIGINT, and SIGHUP.
/// On non-Unix platforms, listens for Ctrl+C only (mapped to `Sigint`).
///
/// This function returns the first signal received. It is intended to be
/// called from the main loop:
///
/// ```ignore
/// let reason = agent_core::signal::wait_for_shutdown().await;
/// match reason {
///     ShutdownReason::Sighup => { /* reload config */ }
///     _ => { /* cancel token, drain, exit */ }
/// }
/// ```
pub async fn wait_for_shutdown() -> ShutdownReason {
    #[cfg(unix)]
    {
        wait_for_shutdown_unix().await
    }

    #[cfg(not(unix))]
    {
        wait_for_shutdown_non_unix().await
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_unix() -> ShutdownReason {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
    let mut sighup = signal(SignalKind::hangup()).expect("failed to register SIGHUP handler");

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM");
            ShutdownReason::Sigterm
        }
        _ = sigint.recv() => {
            tracing::info!("received SIGINT");
            ShutdownReason::Sigint
        }
        _ = sighup.recv() => {
            tracing::info!("received SIGHUP");
            ShutdownReason::Sighup
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_non_unix() -> ShutdownReason {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to register Ctrl+C handler");

    tracing::info!("received Ctrl+C");
    ShutdownReason::Sigint
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_reason_display() {
        assert_eq!(ShutdownReason::Sigterm.to_string(), "SIGTERM");
        assert_eq!(ShutdownReason::Sigint.to_string(), "SIGINT");
        assert_eq!(ShutdownReason::Sighup.to_string(), "SIGHUP");
    }

    #[test]
    fn shutdown_reason_equality() {
        assert_eq!(ShutdownReason::Sigterm, ShutdownReason::Sigterm);
        assert_ne!(ShutdownReason::Sigterm, ShutdownReason::Sigint);
    }
}
