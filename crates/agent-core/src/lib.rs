//! Agent Core — core loop, scheduler, batching, redaction, and signal handling.
//!
//! Implements HU013 (core loop, scheduler, collector trait), HU014 (batching),
//! HU033 (redaction), and part of HU034 (signal handling).

pub mod batcher;
pub mod redaction;
pub mod registry;
pub mod scheduler;
pub mod signal;

// Re-exports for convenient access
pub use batcher::BatcherConfig;
pub use redaction::RedactionEngine;
pub use registry::CollectorRegistry;
pub use signal::{wait_for_shutdown, ShutdownReason};

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("collection failed: {0}")]
    Failed(String),

    #[error("collector timed out")]
    Timeout,

    #[error("platform error: {0}")]
    Platform(#[from] agent_platform::PlatformError),

    #[error("io error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

#[derive(Error, Debug)]
pub enum SchedulerError {
    #[error("scheduler failed: {0}")]
    Failed(String),

    #[error("collector error in {collector}: {source}")]
    Collector {
        collector: String,
        source: CollectorError,
    },

    #[error("channel closed")]
    ChannelClosed,
}

#[derive(Error, Debug)]
pub enum BatcherError {
    #[error("batcher channel closed")]
    ChannelClosed,

    #[error("batch send failed: {0}")]
    SendFailed(String),
}

#[derive(Error, Debug)]
pub enum RedactionError {
    #[error("invalid regex pattern: {0}")]
    InvalidPattern(String),

    #[error("regex compilation error: {0}")]
    RegexError(#[from] regex::Error),
}

// ---------------------------------------------------------------------------
// SignalType
// ---------------------------------------------------------------------------

/// Signal types matching the protobuf `SignalType` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum SignalType {
    Metric = 0,
    Log = 1,
    Trace = 2,
    Event = 3,
    Inventory = 4,
    Heartbeat = 5,
    SecurityEvent = 6,
    CustomEvent = 7,
}

impl SignalType {
    /// Returns the priority of this signal type (lower = higher priority).
    /// Used for buffer-flush ordering when reconnecting after outage.
    ///
    /// Priority order: SecurityEvent(0) > Heartbeat(1) > Metric(2) > Log(3) > rest(4)
    pub fn priority(&self) -> u8 {
        match self {
            SignalType::SecurityEvent => 0,
            SignalType::Heartbeat => 1,
            SignalType::Metric => 2,
            SignalType::Log => 3,
            SignalType::Trace
            | SignalType::Event
            | SignalType::Inventory
            | SignalType::CustomEvent => 4,
        }
    }

    /// Human-readable label for logging and metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignalType::Metric => "metric",
            SignalType::Log => "log",
            SignalType::Trace => "trace",
            SignalType::Event => "event",
            SignalType::Inventory => "inventory",
            SignalType::Heartbeat => "heartbeat",
            SignalType::SecurityEvent => "security_event",
            SignalType::CustomEvent => "custom_event",
        }
    }

    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => SignalType::Metric,
            1 => SignalType::Log,
            2 => SignalType::Trace,
            3 => SignalType::Event,
            4 => SignalType::Inventory,
            5 => SignalType::Heartbeat,
            6 => SignalType::SecurityEvent,
            7 => SignalType::CustomEvent,
            _ => SignalType::Metric,
        }
    }
}

impl std::fmt::Display for SignalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Envelope (Rust-native, not protobuf)
// ---------------------------------------------------------------------------

/// A Rust-native envelope for telemetry data. Will be converted to the
/// protobuf `AgentEnvelope` before transmission.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The type of signal contained in this envelope.
    pub signal_type: SignalType,

    /// Serialized payload bytes (format depends on signal type).
    pub payload: Vec<u8>,

    /// Unix timestamp in nanoseconds when this data was collected.
    pub timestamp_unix_ns: i64,

    /// Whether this envelope was loaded from the on-disk buffer
    /// (i.e. the upstream was unreachable when originally collected).
    pub buffered: bool,

    /// Number of times this envelope has been retried for delivery.
    pub retry_count: u32,
}

impl Envelope {
    /// Estimated in-memory size in bytes (for buffer accounting).
    pub fn estimated_size(&self) -> usize {
        // struct overhead + payload
        std::mem::size_of::<Self>() + self.payload.len()
    }
}

// ---------------------------------------------------------------------------
// Collector trait
// ---------------------------------------------------------------------------

/// Trait that every telemetry collector must implement.
///
/// Each collector runs on its own schedule (defined by `interval()`) and
/// produces zero or more `Envelope` values on each tick.
///
/// We use `Pin<Box<dyn Future>>` instead of `async_trait` to avoid the
/// extra dependency.
pub trait Collector: Send + Sync {
    /// Human-readable name used for logging and metrics (e.g. "cpu", "memory").
    fn name(&self) -> &str;

    /// The signal type this collector produces.
    fn signal_type(&self) -> SignalType;

    /// How often this collector should be invoked.
    fn interval(&self) -> Duration;

    /// Perform a single collection pass and return envelopes.
    fn collect(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Envelope>, CollectorError>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// AgentState — shared counters and identity
// ---------------------------------------------------------------------------

/// Shared mutable state for the running agent.
///
/// Cheaply cloneable (all fields behind `Arc`). Passed to scheduler,
/// batcher, transport, and self-metrics collector.
#[derive(Debug, Clone)]
pub struct AgentState {
    /// Persistent agent identity (UUID v4, written to disk on first boot).
    pub agent_id: String,

    /// SemVer version of the agent binary.
    pub agent_version: String,

    /// Build variant: "linux", "windows", or "lite".
    pub agent_variant: String,

    /// Hostname of the machine this agent runs on.
    pub hostname: String,

    /// Machine / host ID (e.g. /etc/machine-id on Linux).
    pub host_id: String,

    /// OS family string (e.g. "linux", "windows").
    pub os_family: String,

    /// Instant when the agent process started.
    pub start_time: Instant,

    // -- counters --
    /// Total envelopes successfully sent to the upstream.
    pub envelopes_sent: Arc<AtomicU64>,

    /// Total envelopes that failed to send (after retries exhausted).
    pub envelopes_failed: Arc<AtomicU64>,

    /// Total collector-level errors observed.
    pub collector_errors: Arc<AtomicU64>,

    /// Total number of individual redaction substitutions applied.
    pub redactions_total: Arc<AtomicU64>,

    /// Current on-disk buffer usage in bytes.
    pub buffer_used_bytes: Arc<AtomicU64>,

    /// Names of currently registered and active collectors.
    pub active_collectors: Arc<std::sync::RwLock<Vec<String>>>,

    /// SHA-256 hash of the currently loaded configuration file.
    pub config_hash: Arc<std::sync::RwLock<String>>,

    /// Monotonically increasing sequence ID stamped on every envelope batch.
    pub sequence_id: Arc<AtomicU64>,
}

impl AgentState {
    /// Create a new `AgentState` with the given identity fields. All
    /// counters start at zero.
    pub fn new(
        agent_id: String,
        agent_version: String,
        agent_variant: String,
        hostname: String,
        host_id: String,
        os_family: String,
    ) -> Self {
        Self {
            agent_id,
            agent_version,
            agent_variant,
            hostname,
            host_id,
            os_family,
            start_time: Instant::now(),
            envelopes_sent: Arc::new(AtomicU64::new(0)),
            envelopes_failed: Arc::new(AtomicU64::new(0)),
            collector_errors: Arc::new(AtomicU64::new(0)),
            redactions_total: Arc::new(AtomicU64::new(0)),
            buffer_used_bytes: Arc::new(AtomicU64::new(0)),
            active_collectors: Arc::new(std::sync::RwLock::new(Vec::new())),
            config_hash: Arc::new(std::sync::RwLock::new(String::new())),
            sequence_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Atomically increment and return the next sequence ID.
    pub fn next_sequence_id(&self) -> u64 {
        self.sequence_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Seconds elapsed since the agent process started.
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_type_priority_ordering() {
        assert!(SignalType::SecurityEvent.priority() < SignalType::Heartbeat.priority());
        assert!(SignalType::Heartbeat.priority() < SignalType::Metric.priority());
        assert!(SignalType::Metric.priority() < SignalType::Log.priority());
        assert!(SignalType::Log.priority() < SignalType::Trace.priority());
    }

    #[test]
    fn agent_state_sequence_id_monotonic() {
        let state = AgentState::new(
            "test-id".into(),
            "0.1.0".into(),
            "linux".into(),
            "host".into(),
            "host-id".into(),
            "linux".into(),
        );
        assert_eq!(state.next_sequence_id(), 1);
        assert_eq!(state.next_sequence_id(), 2);
        assert_eq!(state.next_sequence_id(), 3);
    }

    #[test]
    fn envelope_estimated_size_includes_payload() {
        let env = Envelope {
            signal_type: SignalType::Metric,
            payload: vec![0u8; 1024],
            timestamp_unix_ns: 0,
            buffered: false,
            retry_count: 0,
        };
        assert!(env.estimated_size() >= 1024);
    }
}
