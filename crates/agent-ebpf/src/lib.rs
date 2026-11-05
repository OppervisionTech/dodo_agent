use thiserror::Error;
#[cfg(feature = "enabled")]
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("eBPF not supported: {0}")]
    NotSupported(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("program load error: {0}")]
    LoadError(String),
    #[error("ring buffer error: {0}")]
    RingBufferError(String),
}

pub type EbpfResult<T> = Result<T, EbpfError>;

/// Events captured by eBPF programs.
#[derive(Debug, Clone)]
pub enum EbpfEvent {
    ProcessExec {
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: String,
        filename: String,
        argv: Vec<String>,
    },
    TcpConnect {
        pid: u32,
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
    },
    FileOpen {
        pid: u32,
        path: String,
        flags: u32,
    },
}

/// eBPF program manager.
///
/// In production, this loads BPF programs via the `aya` crate.
/// For MVP, this is a stub that provides the interface without
/// actual kernel integration (requires Linux kernel >= 5.8 and
/// CAP_BPF + CAP_PERFMON capabilities).
#[cfg(feature = "enabled")]
#[derive(Default)]
pub struct EbpfManager {
    running: bool,
}

#[cfg(feature = "enabled")]
impl EbpfManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if eBPF is available on this system.
    pub fn is_available() -> bool {
        // Check kernel version >= 5.8
        if let Ok(uname) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = uname.trim().split('.').collect();
            if parts.len() >= 2 {
                let major: u32 = parts[0].parse().unwrap_or(0);
                let minor: u32 = parts[1].parse().unwrap_or(0);
                if major > 5 || (major == 5 && minor >= 8) {
                    return true;
                }
            }
            warn!(
                kernel = uname.trim(),
                "eBPF requires kernel >= 5.8, disabling"
            );
        }
        false
    }

    /// Start eBPF programs.
    pub async fn start(
        &mut self,
        _event_tx: tokio::sync::mpsc::Sender<EbpfEvent>,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> EbpfResult<()> {
        if !Self::is_available() {
            return Err(EbpfError::NotSupported(
                "kernel version < 5.8 or BTF not available".to_string(),
            ));
        }

        info!("eBPF programs starting (stub — aya integration pending)");
        self.running = true;

        // Stub: just wait for cancellation
        cancel_token.cancelled().await;
        self.running = false;
        info!("eBPF programs stopped");
        Ok(())
    }

    /// Stop and unload all eBPF programs.
    pub fn stop(&mut self) {
        if self.running {
            info!("unloading eBPF programs");
            self.running = false;
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}

#[cfg(feature = "enabled")]
impl Drop for EbpfManager {
    fn drop(&mut self) {
        self.stop();
    }
}

// When eBPF feature is not enabled, provide a no-op stub
#[cfg(not(feature = "enabled"))]
#[derive(Default)]
pub struct EbpfManager;

#[cfg(not(feature = "enabled"))]
impl EbpfManager {
    pub fn new() -> Self {
        Self
    }
    pub fn is_available() -> bool {
        false
    }
    pub fn is_running(&self) -> bool {
        false
    }
}
