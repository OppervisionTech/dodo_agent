use crate::*;

/// Compression type selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None,
    Zstd,
    Lz4,
}

/// Pseudo-filesystems to exclude from disk metrics.
pub const EXCLUDED_FILESYSTEMS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "proc",
    "sysfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "hugetlbfs",
    "mqueue",
    "fusectl",
    "pstore",
    "binfmt_misc",
    "configfs",
    "autofs",
    "overlay",
    "squashfs",
    "nsfs",
    "tracefs",
];

/// Check if a filesystem type should be excluded.
pub fn is_pseudo_filesystem(fs_type: &str) -> bool {
    EXCLUDED_FILESYSTEMS.contains(&fs_type)
}

/// Virtual block devices whose metrics are noise for host monitoring: loop
/// devices (snap packages, mounted images — dozens per Ubuntu host) and RAM
/// disks. Each one would otherwise add its own disk.io/disk.space series to
/// every host, which is pure storage cost. Accepts "loop0" or "/dev/loop0".
pub fn is_virtual_block_device(device: &str) -> bool {
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    name.starts_with("loop") || name.starts_with("ram")
}

/// Default on-disk path for the generated machine-id fallback (see
/// [`resolve_machine_id`]). Deliberately distinct from the agent_id path
/// (config-driven, `main.rs::load_or_create_agent_id`) — one identifies
/// "which agent install", the other "which physical host".
pub const FALLBACK_HOST_ID_PATH: &str = "/var/lib/aegis-agent/host-id";

/// Resolves a stable machine identity: `/etc/machine-id`, then
/// `/var/lib/dbus/machine-id`, then a UUID generated once and persisted to
/// `fallback_path` so it survives agent restarts even on hosts without
/// systemd/D-Bus. Deliberately never returns a literal `"unknown"` — every
/// host missing both standard files would otherwise collide under the same
/// id, defeating host-level dedup server-side rather than merely degrading it.
pub fn resolve_machine_id(fallback_path: &str) -> String {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(id) = std::fs::read_to_string(path) {
            let id = id.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
    }

    read_or_generate_persisted(fallback_path)
}

/// Reads an id from `path` if present and non-empty; otherwise generates a
/// UUID, persists it to `path`, and returns it. Split out from
/// [`resolve_machine_id`] specifically so this tier is unit-testable without
/// depending on the real host's `/etc/machine-id` being absent.
fn read_or_generate_persisted(path: &str) -> String {
    if let Ok(id) = std::fs::read_to_string(path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, &id);
    id
}

/// TCP state codes from /proc/net/tcp.
pub fn tcp_state_name(state: u8) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Mock platform for tests.
pub struct MockPlatform {
    info: PlatformInfo,
}

impl MockPlatform {
    pub fn new() -> Self {
        Self {
            info: PlatformInfo {
                hostname: "mock-host".to_string(),
                os_family: "linux".to_string(),
                os_version: "Ubuntu 22.04".to_string(),
                kernel_version: "5.15.0".to_string(),
                architecture: "x86_64".to_string(),
                machine_id: "mock-machine-id-12345".to_string(),
                cpu_count_logical: 8,
                cpu_count_physical: 4,
                total_memory_bytes: 16 * 1024 * 1024 * 1024,
                boot_time_unix: 1709900000,
            },
        }
    }
}

impl Default for MockPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for MockPlatform {
    fn info(&self) -> PlatformResult<PlatformInfo> {
        Ok(self.info.clone())
    }

    fn capabilities(&self) -> PlatformResult<PlatformCapabilities> {
        Ok(PlatformCapabilities {
            ebpf_available: false,
            container_detected: false,
            cloud_detected: false,
            kernel_version_major: 5,
            kernel_version_minor: 15,
        })
    }

    fn cpu_times(&self) -> PlatformResult<Vec<CpuTimes>> {
        let total = CpuTimes {
            user: 50000,
            nice: 100,
            system: 20000,
            idle: 900000,
            iowait: 5000,
            irq: 100,
            softirq: 200,
            steal: 0,
            guest: 0,
            guest_nice: 0,
        };
        Ok(vec![total])
    }

    fn load_average(&self) -> PlatformResult<LoadAverage> {
        Ok(LoadAverage {
            one: 1.5,
            five: 2.0,
            fifteen: 3.0,
        })
    }

    fn memory_info(&self) -> PlatformResult<MemoryInfo> {
        Ok(MemoryInfo {
            total_bytes: 16 * 1024 * 1024 * 1024,
            available_bytes: 8 * 1024 * 1024 * 1024,
            free_bytes: 4 * 1024 * 1024 * 1024,
            used_bytes: 8 * 1024 * 1024 * 1024,
            cached_bytes: 4 * 1024 * 1024 * 1024,
            buffers_bytes: 512 * 1024 * 1024,
            swap_total_bytes: 8 * 1024 * 1024 * 1024,
            swap_used_bytes: 0,
            hugepages_total: 0,
            hugepages_free: 0,
        })
    }

    fn disk_spaces(&self) -> PlatformResult<Vec<DiskSpace>> {
        Ok(vec![DiskSpace {
            mount_point: "/".to_string(),
            device: "/dev/sda1".to_string(),
            filesystem: "ext4".to_string(),
            total_bytes: 100 * 1024 * 1024 * 1024,
            used_bytes: 60 * 1024 * 1024 * 1024,
            free_bytes: 40 * 1024 * 1024 * 1024,
            inodes_total: 6553600,
            inodes_used: 1000000,
        }])
    }

    fn disk_io(&self) -> PlatformResult<Vec<DiskIo>> {
        Ok(vec![DiskIo {
            device: "sda".to_string(),
            read_bytes: 1_000_000_000,
            write_bytes: 500_000_000,
            read_ops: 100_000,
            write_ops: 50_000,
            io_time_ms: 60_000,
            weighted_io_time_ms: 120_000,
        }])
    }

    fn network_counters(&self) -> PlatformResult<Vec<NetworkCounters>> {
        Ok(vec![NetworkCounters {
            interface: "eth0".to_string(),
            bytes_recv: 1_000_000,
            bytes_sent: 500_000,
            packets_recv: 10_000,
            packets_sent: 5_000,
            errors_recv: 0,
            errors_sent: 0,
            drops_recv: 0,
            drops_sent: 0,
        }])
    }

    fn tcp_connections(&self) -> PlatformResult<TcpConnections> {
        Ok(TcpConnections {
            established: 10,
            time_wait: 5,
            close_wait: 0,
            total: 15,
        })
    }

    fn processes(&self) -> PlatformResult<Vec<ProcessInfo>> {
        Ok(vec![ProcessInfo {
            pid: 1,
            name: "systemd".to_string(),
            user: "root".to_string(),
            state: 'S',
            cpu_percent: 0.1,
            memory_bytes: 10 * 1024 * 1024,
            memory_percent: 0.06,
            open_fds: 100,
            threads: 1,
            cmdline: "/sbin/init".to_string(),
        }])
    }

    fn listening_ports(&self) -> PlatformResult<Vec<ListeningPort>> {
        Ok(vec![ListeningPort {
            port: 22,
            protocol: "tcp".to_string(),
            pid: 1234,
            process_name: "sshd".to_string(),
            bind_address: "0.0.0.0".to_string(),
        }])
    }

    fn network_interfaces(&self) -> PlatformResult<Vec<NetworkInterface>> {
        Ok(vec![NetworkInterface {
            name: "eth0".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            ipv4: vec!["192.168.1.100".to_string()],
            ipv6: vec![],
            mtu: 1500,
        }])
    }

    fn cloud_info(&self) -> PlatformResult<Option<CloudInfo>> {
        Ok(None)
    }

    fn packages(&self) -> PlatformResult<Vec<PackageInfo>> {
        Ok(vec![])
    }

    fn services(&self) -> PlatformResult<Vec<ServiceInfo>> {
        Ok(vec![])
    }

    fn users(&self) -> PlatformResult<Vec<UserInfo>> {
        Ok(vec![UserInfo {
            username: "root".to_string(),
            uid: 0,
            groups: vec!["root".to_string()],
            shell: "/bin/bash".to_string(),
        }])
    }

    fn cgroup_cpu(&self) -> PlatformResult<Option<CgroupCpuInfo>> {
        Ok(None)
    }

    fn cgroup_memory(&self) -> PlatformResult<Option<CgroupMemoryInfo>> {
        Ok(None)
    }

    fn file_hash(&self, _path: &str) -> PlatformResult<String> {
        Ok("mock-hash-0000000000".to_string())
    }

    fn read_file_string(&self, _path: &str) -> PlatformResult<String> {
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two independent calls against a fresh path (simulating a host with
    /// neither /etc/machine-id nor /var/lib/dbus/machine-id, exercised
    /// directly since real dev/CI machines do have /etc/machine-id) must
    /// agree — the whole point of persisting the generated id is that it
    /// survives agent restarts, unlike the old bare `"unknown"` fallback,
    /// which was both non-unique and "stable" only by accident (always the
    /// same literal string across every such host).
    #[test]
    fn read_or_generate_persisted_survives_across_calls() {
        let dir =
            std::env::temp_dir().join(format!("aegis-agent-test-host-id-{}", uuid::Uuid::new_v4()));
        let path = dir.join("host-id");
        let path = path.to_str().unwrap();

        let first = read_or_generate_persisted(path);
        let second = read_or_generate_persisted(path);

        assert_eq!(first, second, "generated id must persist across calls");
        assert!(!first.is_empty());
        assert_ne!(
            first, "unknown",
            "must never fall back to the literal \"unknown\""
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn virtual_block_devices_are_detected() {
        for dev in ["loop0", "/dev/loop12", "ram0", "/dev/ram15"] {
            assert!(is_virtual_block_device(dev), "{dev}");
        }
        for dev in [
            "sda",
            "/dev/sda1",
            "nvme0n1",
            "dm-0",
            "/dev/mapper/root",
            "xvda",
            "vda",
        ] {
            assert!(!is_virtual_block_device(dev), "{dev}");
        }
    }
}
