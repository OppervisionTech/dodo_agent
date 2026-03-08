//! Agent collectors — telemetry collection modules.
//!
//! Each collector implements the `agent_core::Collector` trait and is
//! registered with the scheduler at agent startup. Collectors are
//! independent modules that can be enabled/disabled via config.

pub mod helpers;

pub mod certs;
pub mod cpu;
pub mod disk;
pub mod heartbeat;
pub mod inventory;
pub mod kubernetes;
pub mod logs;
pub mod memory;
pub mod network;
pub mod otel;
pub mod process;
pub mod security;
pub mod self_metrics;

// Re-export collector structs for convenient access
pub use certs::CertsCollector;
pub use cpu::CpuCollector;
pub use disk::DiskCollector;
pub use heartbeat::HeartbeatCollector;
pub use inventory::InventoryCollector;
pub use kubernetes::KubernetesCollector;
pub use logs::LogsCollector;
pub use memory::MemoryCollector;
pub use network::NetworkCollector;
pub use otel::OtelCollector;
pub use process::ProcessCollector;
pub use security::SecurityCollector;
pub use self_metrics::SelfMetricsCollector;
