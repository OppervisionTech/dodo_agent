pub mod common;

#[cfg(feature = "linux")]
pub mod linux;

#[cfg(feature = "windows")]
pub mod windows;

#[cfg(feature = "lite")]
pub mod lite;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("not supported on this platform: {0}")]
    NotSupported(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

pub type PlatformResult<T> = Result<T, PlatformError>;

/// Host identification and OS information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlatformInfo {
    pub hostname: String,
    pub os_family: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub machine_id: String,
    pub cpu_count_logical: u32,
    pub cpu_count_physical: u32,
    pub total_memory_bytes: u64,
    pub boot_time_unix: u64,
}

/// CPU time counters from /proc/stat or equivalent.
#[derive(Debug, Clone, Default)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    pub fn busy(&self) -> u64 {
        self.total() - self.idle - self.iowait
    }
}

/// Load average values.
#[derive(Debug, Clone, Default)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

/// Memory information from /proc/meminfo or equivalent.
#[derive(Debug, Clone, Default)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub cached_bytes: u64,
    pub buffers_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub hugepages_total: u64,
    pub hugepages_free: u64,
}

/// Disk space information per mount point.
#[derive(Debug, Clone)]
pub struct DiskSpace {
    pub mount_point: String,
    pub device: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub inodes_total: u64,
    pub inodes_used: u64,
}

/// Disk I/O counters per device (cumulative).
#[derive(Debug, Clone, Default)]
pub struct DiskIo {
    pub device: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub io_time_ms: u64,
    pub weighted_io_time_ms: u64,
}

/// Network interface counters (cumulative).
#[derive(Debug, Clone, Default)]
pub struct NetworkCounters {
    pub interface: String,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub packets_sent: u64,
    pub errors_recv: u64,
    pub errors_sent: u64,
    pub drops_recv: u64,
    pub drops_sent: u64,
}

/// TCP connection state counts.
#[derive(Debug, Clone, Default)]
pub struct TcpConnections {
    pub established: u64,
    pub time_wait: u64,
    pub close_wait: u64,
    pub total: u64,
}

/// Process info snapshot.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub state: char,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub memory_percent: f64,
    pub open_fds: i64,
    pub threads: u32,
    pub cmdline: String,
}

/// Listening port info.
#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: String,
    pub pid: u32,
    pub process_name: String,
    pub bind_address: String,
}

/// Network interface info (for inventory).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mtu: u32,
}

/// Cloud provider metadata.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CloudInfo {
    pub provider: String,
    pub region: String,
    pub instance_type: String,
    pub instance_id: String,
    pub vpc_id: String,
}

/// Installed package info.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub manager: String,
}

/// System service info.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub status: String,
    pub enabled: bool,
}

/// System user info.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub groups: Vec<String>,
    pub shell: String,
}

/// Cgroup CPU limits (for container detection).
#[derive(Debug, Clone, Default)]
pub struct CgroupCpuInfo {
    pub has_limit: bool,
    pub limit_cores: f64,
    pub usage_ns: u64,
}

/// Cgroup memory limits.
#[derive(Debug, Clone, Default)]
pub struct CgroupMemoryInfo {
    pub has_limit: bool,
    pub limit_bytes: u64,
    pub usage_bytes: u64,
}

/// Capabilities of the current platform detected at runtime.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    pub ebpf_available: bool,
    pub container_detected: bool,
    pub cloud_detected: bool,
    pub kernel_version_major: u32,
    pub kernel_version_minor: u32,
}

/// Compression selection based on variant.
pub fn default_compression() -> common::CompressionType {
    #[cfg(feature = "lite")]
    return common::CompressionType::Lz4;
    #[cfg(not(feature = "lite"))]
    return common::CompressionType::Zstd;
}

/// Platform abstraction trait for OS-specific operations.
pub trait Platform: Send + Sync {
    fn info(&self) -> PlatformResult<PlatformInfo>;
    fn capabilities(&self) -> PlatformResult<PlatformCapabilities>;
    fn cpu_times(&self) -> PlatformResult<Vec<CpuTimes>>;
    fn load_average(&self) -> PlatformResult<LoadAverage>;
    fn memory_info(&self) -> PlatformResult<MemoryInfo>;
    fn disk_spaces(&self) -> PlatformResult<Vec<DiskSpace>>;
    fn disk_io(&self) -> PlatformResult<Vec<DiskIo>>;
    fn network_counters(&self) -> PlatformResult<Vec<NetworkCounters>>;
    fn tcp_connections(&self) -> PlatformResult<TcpConnections>;
    fn processes(&self) -> PlatformResult<Vec<ProcessInfo>>;
    fn listening_ports(&self) -> PlatformResult<Vec<ListeningPort>>;
    fn network_interfaces(&self) -> PlatformResult<Vec<NetworkInterface>>;
    fn cloud_info(&self) -> PlatformResult<Option<CloudInfo>>;
    fn packages(&self) -> PlatformResult<Vec<PackageInfo>>;
    fn services(&self) -> PlatformResult<Vec<ServiceInfo>>;
    fn users(&self) -> PlatformResult<Vec<UserInfo>>;
    fn cgroup_cpu(&self) -> PlatformResult<Option<CgroupCpuInfo>>;
    fn cgroup_memory(&self) -> PlatformResult<Option<CgroupMemoryInfo>>;
    fn file_hash(&self, path: &str) -> PlatformResult<String>;
    fn read_file_string(&self, path: &str) -> PlatformResult<String>;
}

/// Create the appropriate platform implementation for the current build.
pub fn create_platform() -> Box<dyn Platform> {
    #[cfg(feature = "linux")]
    return Box::new(linux::LinuxPlatform::new());

    #[cfg(feature = "windows")]
    return Box::new(windows::WindowsPlatform::new());

    #[cfg(feature = "lite")]
    return Box::new(lite::LitePlatform::new());

    #[cfg(not(any(feature = "linux", feature = "windows", feature = "lite")))]
    return Box::new(common::MockPlatform::new());
}
