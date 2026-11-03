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

/// Default on-disk path for the generated machine-id fallback (see
/// [`resolve_machine_id`]). Deliberately distinct from the agent_id path
/// (config-driven, `main.rs::load_or_create_agent_id`) — one identifies
/// "which agent install", the other "which physical host".
pub const FALLBACK_HOST_ID_PATH: &str = "/var/lib/aegis/host-id";
pub(crate) const LEGACY_HOST_ID_PATH: &str = "/var/lib/aegis-agent/host-id";

/// Resolves a stable machine identity: `/etc/machine-id`, then
/// `/var/lib/dbus/machine-id`, then a UUID generated once and persisted to
/// `fallback_path` so it survives agent restarts even on hosts without
/// systemd/D-Bus. Deliberately never returns a literal `"unknown"` — every
/// host missing both standard files would otherwise collide under the same
/// id, defeating host-level dedup server-side rather than merely degrading it.
pub fn resolve_machine_id(fallback_path: &str) -> PlatformResult<String> {
    resolve_machine_id_from_paths(
        [
            std::path::PathBuf::from("/etc/machine-id"),
            std::path::PathBuf::from("/var/lib/dbus/machine-id"),
        ],
        fallback_path,
        Some(std::path::Path::new(LEGACY_HOST_ID_PATH)),
    )
}

pub(crate) fn resolve_machine_id_from_paths(
    paths: [std::path::PathBuf; 2],
    fallback_path: &str,
    legacy_path: Option<&std::path::Path>,
) -> PlatformResult<String> {
    for path in paths {
        if let Some(id) = read_identity(&path) {
            return Ok(id);
        }
    }
    if let Some(id) = read_persisted_identity(std::path::Path::new(fallback_path))? {
        return Ok(id);
    }
    let legacy = match legacy_path {
        Some(path) => read_persisted_identity(path)?,
        None => None,
    };
    read_or_generate_persisted(fallback_path, legacy)
}

fn read_identity(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
}

// A missing state file permits first installation; unreadable/corrupt state must
// never be mistaken for a new physical host.
fn read_persisted_identity(path: &std::path::Path) -> PlatformResult<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(identity) if !identity.trim().is_empty() => Ok(Some(identity.trim().to_string())),
        Ok(_) => Err(PlatformError::Parse(
            "persisted host identity is empty".to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Generate or migrate identity only when its state can actually be persisted.
/// create_new prevents concurrent first starts from overwriting the winning id.
fn read_or_generate_persisted(path: &str, legacy: Option<String>) -> PlatformResult<String> {
    use std::io::Write;
    if let Some(id) = read_persisted_identity(std::path::Path::new(path))? {
        return Ok(id);
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let id = legacy.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return read_persisted_identity(std::path::Path::new(path))?.ok_or_else(|| {
                PlatformError::Parse(
                    "persisted host identity disappeared while initializing".to_string(),
                )
            });
        }
        Err(error) => return Err(error.into()),
    };
    file.write_all(id.as_bytes())?;
    file.sync_all()?;
    Ok(id)
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

        let first = read_or_generate_persisted(path, None).unwrap();
        let second = read_or_generate_persisted(path, None).unwrap();

        assert_eq!(first, second, "generated id must persist across calls");
        assert!(!first.is_empty());
        assert_ne!(
            first, "unknown",
            "must never fall back to the literal \"unknown\""
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_first_starts_never_overwrite_the_winning_identity() {
        let directory =
            std::env::temp_dir().join(format!("dodo-host-id-race-{}", uuid::Uuid::new_v4()));
        let path = directory.join("host-id");
        let barrier = std::sync::Barrier::new(16);
        let identities = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        read_or_generate_persisted(path.to_str().unwrap(), None)
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| match handle.join().unwrap() {
                    Ok(identity) => Some(identity),
                    // A second process may see the first writer's empty file;
                    // it fails closed and can retry after initialization.
                    Err(PlatformError::Parse(_)) => None,
                    Err(error) => panic!("unexpected state IO failure: {error}"),
                })
                .collect::<Vec<_>>()
        });
        assert!(!identities.is_empty());
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(uuid::Uuid::parse_str(&persisted).is_ok());
        assert!(identities.iter().all(|identity| identity == &persisted));
        assert_eq!(
            read_or_generate_persisted(path.to_str().unwrap(), None).unwrap(),
            persisted
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
