//! Windows platform stub.
//!
//! All methods return `PlatformError::NotSupported` — actual WMI-based
//! collection is planned for V2.

use crate::*;

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper that builds a `NotSupported` error with the standard V2 message.
fn not_supported<T>() -> PlatformResult<T> {
    Err(PlatformError::NotSupported(
        "Windows support planned for V2".to_string(),
    ))
}

impl Platform for WindowsPlatform {
    fn info(&self) -> PlatformResult<PlatformInfo> {
        not_supported()
    }

    fn capabilities(&self) -> PlatformResult<PlatformCapabilities> {
        not_supported()
    }

    fn cpu_times(&self) -> PlatformResult<Vec<CpuTimes>> {
        not_supported()
    }

    fn load_average(&self) -> PlatformResult<LoadAverage> {
        not_supported()
    }

    fn memory_info(&self) -> PlatformResult<MemoryInfo> {
        not_supported()
    }

    fn disk_spaces(&self) -> PlatformResult<Vec<DiskSpace>> {
        not_supported()
    }

    fn disk_io(&self) -> PlatformResult<Vec<DiskIo>> {
        not_supported()
    }

    fn network_counters(&self) -> PlatformResult<Vec<NetworkCounters>> {
        not_supported()
    }

    fn tcp_connections(&self) -> PlatformResult<TcpConnections> {
        not_supported()
    }

    fn processes(&self) -> PlatformResult<Vec<ProcessInfo>> {
        not_supported()
    }

    fn listening_ports(&self) -> PlatformResult<Vec<ListeningPort>> {
        not_supported()
    }

    fn network_interfaces(&self) -> PlatformResult<Vec<NetworkInterface>> {
        not_supported()
    }

    fn cloud_info(&self) -> PlatformResult<Option<CloudInfo>> {
        not_supported()
    }

    fn packages(&self) -> PlatformResult<Vec<PackageInfo>> {
        not_supported()
    }

    fn services(&self) -> PlatformResult<Vec<ServiceInfo>> {
        not_supported()
    }

    fn users(&self) -> PlatformResult<Vec<UserInfo>> {
        not_supported()
    }

    fn cgroup_cpu(&self) -> PlatformResult<Option<CgroupCpuInfo>> {
        not_supported()
    }

    fn cgroup_memory(&self) -> PlatformResult<Option<CgroupMemoryInfo>> {
        not_supported()
    }

    fn file_hash(&self, _path: &str) -> PlatformResult<String> {
        not_supported()
    }

    fn read_file_string(&self, _path: &str) -> PlatformResult<String> {
        not_supported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_methods_return_not_supported() {
        let p = WindowsPlatform::new();

        assert!(matches!(p.info(), Err(PlatformError::NotSupported(_))));
        assert!(matches!(
            p.capabilities(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(p.cpu_times(), Err(PlatformError::NotSupported(_))));
        assert!(matches!(
            p.load_average(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.memory_info(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.disk_spaces(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(p.disk_io(), Err(PlatformError::NotSupported(_))));
        assert!(matches!(
            p.network_counters(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.tcp_connections(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(p.processes(), Err(PlatformError::NotSupported(_))));
        assert!(matches!(
            p.listening_ports(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.network_interfaces(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.cloud_info(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(p.packages(), Err(PlatformError::NotSupported(_))));
        assert!(matches!(p.services(), Err(PlatformError::NotSupported(_))));
        assert!(matches!(p.users(), Err(PlatformError::NotSupported(_))));
        assert!(matches!(
            p.cgroup_cpu(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.cgroup_memory(),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.file_hash("/any"),
            Err(PlatformError::NotSupported(_))
        ));
        assert!(matches!(
            p.read_file_string("/any"),
            Err(PlatformError::NotSupported(_))
        ));
    }
}
