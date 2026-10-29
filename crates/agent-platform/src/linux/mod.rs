use crate::*;

use crate::common::{resolve_machine_id_from_paths, FALLBACK_HOST_ID_PATH};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// statvfs field widths differ across libc targets; normalize without assuming
// that the native counter is always u64.
fn filesystem_count(value: impl Into<u64>) -> u64 {
    value.into()
}

/// Linux-specific implementation of the Platform trait.
///
/// Reads system information directly from /proc and /sys filesystems.
/// No external crates are used for procfs parsing — all parsing is manual.
pub struct LinuxPlatform {
    root: PathBuf,
    command_dir: Option<PathBuf>,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
            command_dir: None,
        }
    }

    fn path(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    fn command(&self, program: &str) -> Command {
        match &self.command_dir {
            Some(directory) => Command::new(directory.join(program)),
            None => Command::new(program),
        }
    }

    /// Parse a key-value file like /proc/meminfo where lines are "Key: value kB".
    fn parse_kv_file(content: &str) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let key = parts[0].trim_end_matches(':').to_string();
                if let Ok(val) = parts[1].parse::<u64>() {
                    map.insert(key, val);
                }
            }
        }
        map
    }

    /// Parse kernel version string like "5.15.0-100-generic" into (major, minor).
    fn parse_kernel_version(version: &str) -> (u32, u32) {
        let parts: Vec<&str> = version.split('.').collect();
        let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        (major, minor)
    }

    /// Read the uid-to-username mapping from /etc/passwd.
    fn uid_to_username_map(&self) -> HashMap<u32, String> {
        let mut map = HashMap::new();
        if let Ok(content) = fs::read_to_string(self.path("/etc/passwd")) {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 3 {
                    if let Ok(uid) = fields[2].parse::<u32>() {
                        map.insert(uid, fields[0].to_string());
                    }
                }
            }
        }
        map
    }

    /// Parse a hex-encoded IP address from /proc/net/tcp into a human-readable string.
    /// Format in /proc/net/tcp: "0100007F:0050" -> "127.0.0.1:80"
    fn parse_hex_addr_port(hex_addr_port: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = hex_addr_port.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let addr_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16).ok()?;

        if addr_hex.len() == 8 {
            // IPv4: stored as little-endian 32-bit hex
            let addr_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
            let a = addr_u32 & 0xFF;
            let b = (addr_u32 >> 8) & 0xFF;
            let c = (addr_u32 >> 16) & 0xFF;
            let d = (addr_u32 >> 24) & 0xFF;
            Some((format!("{}.{}.{}.{}", a, b, c, d), port))
        } else if addr_hex.len() == 32 {
            // procfs encodes all four 32-bit words in native little-endian order.
            // Reject non-ASCII data before slicing byte offsets.
            if !addr_hex.is_ascii() {
                return None;
            }
            let mut octets = [0_u8; 16];
            for (word, output) in addr_hex
                .as_bytes()
                .chunks_exact(8)
                .zip(octets.chunks_exact_mut(4))
            {
                let encoded = std::str::from_utf8(word).ok()?;
                output.copy_from_slice(&u32::from_str_radix(encoded, 16).ok()?.to_le_bytes());
            }
            Some((std::net::Ipv6Addr::from(octets).to_string(), port))
        } else {
            None
        }
    }

    /// Find the PID that owns a given inode from /proc/[pid]/fd.
    fn find_pid_for_inode(&self, inode: u64) -> Option<(u32, String)> {
        let proc_dir = match fs::read_dir(self.path("/proc")) {
            Ok(d) => d,
            Err(_) => return None,
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd_path = format!("/proc/{}/fd", pid);
            let fd_dir = match fs::read_dir(self.path(&fd_path)) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for fd_entry in fd_dir.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    let link_str = link.to_string_lossy().to_string();
                    if link_str == format!("socket:[{}]", inode) {
                        let proc_name =
                            fs::read_to_string(self.path(&format!("/proc/{}/comm", pid)))
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                        return Some((pid, proc_name));
                    }
                }
            }
        }
        None
    }

    /// Count physical CPU cores from /proc/cpuinfo by counting unique core id + physical id pairs.
    fn count_physical_cores(cpuinfo: &str) -> u32 {
        let mut core_ids: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        let mut current_physical = String::new();

        for line in cpuinfo.lines() {
            if line.starts_with("physical id") {
                if let Some(val) = line.split(':').nth(1) {
                    current_physical = val.trim().to_string();
                }
            } else if line.starts_with("core id") {
                if let Some(val) = line.split(':').nth(1) {
                    let core_id = val.trim().to_string();
                    core_ids.insert((current_physical.clone(), core_id));
                }
            }
        }

        let count = core_ids.len() as u32;
        if count == 0 {
            // Fallback: count "processor" lines
            cpuinfo
                .lines()
                .filter(|l| l.starts_with("processor"))
                .count() as u32
        } else {
            count
        }
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for LinuxPlatform {
    fn info(&self) -> PlatformResult<PlatformInfo> {
        let hostname = fs::read_to_string(self.path("/proc/sys/kernel/hostname"))
            .map(|s| s.trim().to_string())
            .map_err(PlatformError::Io)?;

        let kernel_version = fs::read_to_string(self.path("/proc/sys/kernel/osrelease"))
            .map(|s| s.trim().to_string())
            .map_err(PlatformError::Io)?;

        let os_version = fs::read_to_string(self.path("/etc/os-release"))
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| {
                        l.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string()
                    })
            })
            .unwrap_or_else(|| "Linux".to_string());

        let architecture = fs::read_to_string(self.path("/proc/sys/kernel/arch"))
            .or_else(|_| {
                self.command("uname")
                    .arg("-m")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            })
            .unwrap_or_else(|_| "unknown".to_string());

        let machine_id = resolve_machine_id_from_paths(
            [
                self.path("/etc/machine-id"),
                self.path("/var/lib/dbus/machine-id"),
            ],
            self.path(FALLBACK_HOST_ID_PATH)
                .to_str()
                .ok_or_else(|| PlatformError::Parse("host-id path is not UTF-8".to_string()))?,
        );

        let cpuinfo = fs::read_to_string(self.path("/proc/cpuinfo")).map_err(PlatformError::Io)?;
        let cpu_count_logical = cpuinfo
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count() as u32;
        let cpu_count_physical = Self::count_physical_cores(&cpuinfo);

        let meminfo = fs::read_to_string(self.path("/proc/meminfo")).map_err(PlatformError::Io)?;
        let mem_map = Self::parse_kv_file(&meminfo);
        let total_memory_bytes = mem_map.get("MemTotal").copied().unwrap_or(0) * 1024;

        let stat_content =
            fs::read_to_string(self.path("/proc/stat")).map_err(PlatformError::Io)?;
        let boot_time_unix = stat_content
            .lines()
            .find(|l| l.starts_with("btime "))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(PlatformInfo {
            hostname,
            os_family: "linux".to_string(),
            os_version,
            kernel_version,
            architecture,
            machine_id,
            cpu_count_logical,
            cpu_count_physical,
            total_memory_bytes,
            boot_time_unix,
        })
    }

    fn capabilities(&self) -> PlatformResult<PlatformCapabilities> {
        let kernel_version = fs::read_to_string(self.path("/proc/sys/kernel/osrelease"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "0.0".to_string());
        let (major, minor) = Self::parse_kernel_version(&kernel_version);

        // eBPF requires kernel >= 5.8 for full BTF/CO-RE support
        let ebpf_available = major > 5 || (major == 5 && minor >= 8);

        // Container detection: check /.dockerenv or cgroup contents
        let container_detected = self.path("/.dockerenv").exists()
            || fs::read_to_string(self.path("/proc/1/cgroup"))
                .map(|c| {
                    c.contains("/docker/")
                        || c.contains("/kubepods/")
                        || c.contains("/lxc/")
                        || c.contains("/containerd/")
                })
                .unwrap_or(false);

        // Cloud detection: quick check via DMI or product info
        let cloud_detected = fs::read_to_string(self.path("/sys/class/dmi/id/sys_vendor"))
            .map(|v| {
                let v = v.trim().to_lowercase();
                v.contains("amazon") || v.contains("google") || v.contains("microsoft")
            })
            .unwrap_or(false);

        Ok(PlatformCapabilities {
            ebpf_available,
            container_detected,
            cloud_detected,
            kernel_version_major: major,
            kernel_version_minor: minor,
        })
    }

    fn cpu_times(&self) -> PlatformResult<Vec<CpuTimes>> {
        let content = fs::read_to_string(self.path("/proc/stat")).map_err(PlatformError::Io)?;
        let mut result = Vec::new();

        for line in content.lines() {
            if !line.starts_with("cpu") {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            // "cpu" (total) or "cpu0", "cpu1", etc.
            if fields.len() < 8 {
                continue;
            }

            let parse =
                |idx: usize| -> u64 { fields.get(idx).and_then(|s| s.parse().ok()).unwrap_or(0) };

            result.push(CpuTimes {
                user: parse(1),
                nice: parse(2),
                system: parse(3),
                idle: parse(4),
                iowait: parse(5),
                irq: parse(6),
                softirq: parse(7),
                steal: parse(8),
                guest: parse(9),
                guest_nice: parse(10),
            });
        }

        if result.is_empty() {
            return Err(PlatformError::Parse(
                "no cpu lines found in /proc/stat".to_string(),
            ));
        }

        Ok(result)
    }

    fn load_average(&self) -> PlatformResult<LoadAverage> {
        let content = fs::read_to_string(self.path("/proc/loadavg")).map_err(PlatformError::Io)?;
        let fields: Vec<&str> = content.split_whitespace().collect();

        if fields.len() < 3 {
            return Err(PlatformError::Parse(
                "unexpected format in /proc/loadavg".to_string(),
            ));
        }

        let one = fields[0]
            .parse::<f64>()
            .map_err(|e| PlatformError::Parse(format!("load1: {}", e)))?;
        let five = fields[1]
            .parse::<f64>()
            .map_err(|e| PlatformError::Parse(format!("load5: {}", e)))?;
        let fifteen = fields[2]
            .parse::<f64>()
            .map_err(|e| PlatformError::Parse(format!("load15: {}", e)))?;

        Ok(LoadAverage { one, five, fifteen })
    }

    fn memory_info(&self) -> PlatformResult<MemoryInfo> {
        let content = fs::read_to_string(self.path("/proc/meminfo")).map_err(PlatformError::Io)?;
        let kv = Self::parse_kv_file(&content);

        let get_kb = |key: &str| -> u64 { kv.get(key).copied().unwrap_or(0) * 1024 };

        let total = get_kb("MemTotal");
        let free = get_kb("MemFree");
        let available = get_kb("MemAvailable");
        let buffers = get_kb("Buffers");
        let cached = get_kb("Cached");
        let swap_total = get_kb("SwapTotal");
        let swap_free = get_kb("SwapFree");
        let hugepages_total = kv.get("HugePages_Total").copied().unwrap_or(0);
        let hugepages_free = kv.get("HugePages_Free").copied().unwrap_or(0);

        let used = total
            .saturating_sub(free)
            .saturating_sub(buffers)
            .saturating_sub(cached);

        Ok(MemoryInfo {
            total_bytes: total,
            available_bytes: available,
            free_bytes: free,
            used_bytes: used,
            cached_bytes: cached,
            buffers_bytes: buffers,
            swap_total_bytes: swap_total,
            swap_used_bytes: swap_total.saturating_sub(swap_free),
            hugepages_total,
            hugepages_free,
        })
    }

    fn disk_spaces(&self) -> PlatformResult<Vec<DiskSpace>> {
        let mounts = fs::read_to_string(self.path("/proc/mounts")).map_err(PlatformError::Io)?;
        let mut result = Vec::new();
        let mut seen_devices: std::collections::HashSet<String> = std::collections::HashSet::new();

        for line in mounts.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }

            let device = fields[0];
            let mount_point = fields[1];
            let fs_type = fields[2];

            // Skip pseudo-filesystems
            if common::is_pseudo_filesystem(fs_type) {
                continue;
            }

            // Skip non-device mounts (those not starting with /)
            if !device.starts_with('/') {
                continue;
            }

            // Skip duplicate devices (keep first mount point)
            if !seen_devices.insert(device.to_string()) {
                continue;
            }

            let c_path = match CString::new(self.path(mount_point).as_os_str().as_encoded_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

            // SAFETY: We pass a valid null-terminated C string (c_path) that was just
            // constructed from a mount point read from /proc/mounts. The stat variable
            // is a properly zeroed statvfs struct allocated on the stack. libc::statvfs
            // only writes to the stat output parameter and does not retain the pointer.
            // This is the one acceptable use of unsafe in the agent, required because
            // there is no safe Rust API in std for querying filesystem space.
            let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };

            if ret != 0 {
                // Permission denied or unavailable mount — skip silently
                continue;
            }

            let block_size = filesystem_count(stat.f_frsize);
            let total_bytes = (stat.f_blocks as u64) * block_size;
            let free_bytes = (stat.f_bfree as u64) * block_size;
            let used_bytes = total_bytes.saturating_sub(free_bytes);

            // Skip zero-size filesystems
            if total_bytes == 0 {
                continue;
            }

            result.push(DiskSpace {
                mount_point: mount_point.to_string(),
                device: device.to_string(),
                filesystem: fs_type.to_string(),
                total_bytes,
                used_bytes,
                free_bytes,
                inodes_total: stat.f_files as u64,
                inodes_used: (stat.f_files as u64).saturating_sub(stat.f_ffree as u64),
            });
        }

        Ok(result)
    }

    fn disk_io(&self) -> PlatformResult<Vec<DiskIo>> {
        let content =
            fs::read_to_string(self.path("/proc/diskstats")).map_err(PlatformError::Io)?;
        let mut result = Vec::new();

        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // /proc/diskstats has 14+ fields: major minor name rd_ios rd_merges rd_sectors rd_ticks
            //   wr_ios wr_merges wr_sectors wr_ticks ios_in_progress io_ticks weighted_io_ticks ...
            if fields.len() < 14 {
                continue;
            }

            let device = fields[2].to_string();

            // Skip partitions (e.g., sda1) — only report whole devices and device-mapper
            // A simple heuristic: if the device name ends with a digit and is not a dm- device,
            // check if a parent device exists (e.g. sda for sda1). We keep dm- and loop devices.
            let is_partition = device
                .chars()
                .last()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && !device.starts_with("dm-")
                && !device.starts_with("loop")
                && !device.starts_with("nvme"); // nvme0n1 is a device, nvme0n1p1 is a partition

            // For nvme, partitions contain 'p' followed by digits (nvme0n1p1)
            let is_nvme_partition = device.starts_with("nvme") && device.contains('p') && {
                let after_p = device.rsplit('p').next().unwrap_or("");
                after_p.chars().all(|c| c.is_ascii_digit()) && !after_p.is_empty() && {
                    // Check that the 'p' is not part of the base device name (nvme0n1 has no 'p')
                    let p_idx = device.rfind('p').unwrap_or(0);
                    p_idx > 0
                        && device[..p_idx]
                            .chars()
                            .last()
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(false)
                }
            };

            if is_partition || is_nvme_partition {
                continue;
            }

            let parse =
                |idx: usize| -> u64 { fields.get(idx).and_then(|s| s.parse().ok()).unwrap_or(0) };

            let read_ops = parse(3);
            let read_sectors = parse(5);
            let write_ops = parse(7);
            let write_sectors = parse(9);
            let io_time_ms = parse(12);
            let weighted_io_time_ms = parse(13);

            // Skip devices with zero I/O (probably unused loop devices)
            if read_ops == 0 && write_ops == 0 {
                continue;
            }

            // Sectors are typically 512 bytes
            result.push(DiskIo {
                device,
                read_bytes: read_sectors * 512,
                write_bytes: write_sectors * 512,
                read_ops,
                write_ops,
                io_time_ms,
                weighted_io_time_ms,
            });
        }

        Ok(result)
    }

    fn network_counters(&self) -> PlatformResult<Vec<NetworkCounters>> {
        let content = fs::read_to_string(self.path("/proc/net/dev")).map_err(PlatformError::Io)?;
        let mut result = Vec::new();

        for line in content.lines().skip(2) {
            // Skip the 2 header lines
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Format: "iface: bytes packets errs drop fifo frame compressed multicast | bytes packets ..."
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }

            let interface = parts[0].trim().to_string();

            // Filter loopback
            if interface == "lo" {
                continue;
            }

            let fields: Vec<&str> = parts[1].split_whitespace().collect();
            if fields.len() < 16 {
                continue;
            }

            let parse =
                |idx: usize| -> u64 { fields.get(idx).and_then(|s| s.parse().ok()).unwrap_or(0) };

            result.push(NetworkCounters {
                interface,
                bytes_recv: parse(0),
                packets_recv: parse(1),
                errors_recv: parse(2),
                drops_recv: parse(3),
                bytes_sent: parse(8),
                packets_sent: parse(9),
                errors_sent: parse(10),
                drops_sent: parse(11),
            });
        }

        Ok(result)
    }

    fn tcp_connections(&self) -> PlatformResult<TcpConnections> {
        let mut established: u64 = 0;
        let mut time_wait: u64 = 0;
        let mut close_wait: u64 = 0;
        let mut total: u64 = 0;

        // Parse both IPv4 and IPv6 TCP connections
        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            let content = match fs::read_to_string(self.path(path)) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    continue;
                }

                let state = match u8::from_str_radix(fields[3], 16) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                total += 1;
                match state {
                    0x01 => established += 1,
                    0x06 => time_wait += 1,
                    0x08 => close_wait += 1,
                    _ => {}
                }
            }
        }

        Ok(TcpConnections {
            established,
            time_wait,
            close_wait,
            total,
        })
    }

    fn processes(&self) -> PlatformResult<Vec<ProcessInfo>> {
        let proc_dir = fs::read_dir(self.path("/proc")).map_err(PlatformError::Io)?;
        let uid_map = self.uid_to_username_map();

        // Read total memory once for memory_percent calculation
        let total_memory = fs::read_to_string(self.path("/proc/meminfo"))
            .ok()
            .and_then(|c| {
                Self::parse_kv_file(&c)
                    .get("MemTotal")
                    .copied()
                    .map(|v| v * 1024)
            })
            .unwrap_or(1); // avoid div by zero

        let mut result = Vec::new();

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read /proc/[pid]/stat
            let stat_path = format!("/proc/{}/stat", pid);
            let stat_content = match fs::read_to_string(self.path(&stat_path)) {
                Ok(c) => c,
                Err(_) => continue, // process may have exited
            };

            // Parse /proc/[pid]/stat — name is in parens and may contain spaces
            // Format: pid (comm) state ppid pgrp session tty_nr ...
            let comm_start = match stat_content.find('(') {
                Some(i) => i,
                None => continue,
            };
            let comm_end = match stat_content.rfind(')') {
                Some(i) => i,
                None => continue,
            };

            let Some(process_name) = stat_content.get(comm_start + 1..comm_end) else {
                continue;
            };
            let process_name = process_name.to_string();
            let after_comm = stat_content
                .get(comm_end + 1..)
                .unwrap_or_default()
                .trim_start();
            let stat_fields: Vec<&str> = after_comm.split_whitespace().collect();

            if stat_fields.is_empty() {
                continue;
            }

            let state = stat_fields[0].chars().next().unwrap_or('?');

            // Field indices after comm (0-based from after_comm):
            // 0=state, 1=ppid, ..., 11=utime, 12=stime, ..., 17=num_threads, ..., 21=rss
            let threads = stat_fields
                .get(17)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);

            let rss_pages = stat_fields
                .get(21)
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let page_size: u64 = 4096; // standard Linux page size
            let memory_bytes = (rss_pages.max(0) as u64) * page_size;
            let memory_percent = if total_memory > 0 {
                (memory_bytes as f64 / total_memory as f64) * 100.0
            } else {
                0.0
            };

            // Read UID from /proc/[pid]/status
            let status_path = format!("/proc/{}/status", pid);
            let uid = fs::read_to_string(self.path(&status_path))
                .ok()
                .and_then(|content| {
                    content
                        .lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|s| s.parse::<u32>().ok())
                })
                .unwrap_or(0);

            let user = uid_map
                .get(&uid)
                .cloned()
                .unwrap_or_else(|| uid.to_string());

            // Read open file descriptors count
            let fd_path = format!("/proc/{}/fd", pid);
            let open_fds = fs::read_dir(self.path(&fd_path))
                .map(|entries| entries.count() as i64)
                .unwrap_or(-1);

            // Read command line
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            let cmdline = fs::read_to_string(self.path(&cmdline_path))
                .map(|c| c.replace('\0', " ").trim().to_string())
                .unwrap_or_default();

            result.push(ProcessInfo {
                pid,
                name: process_name,
                user,
                state,
                cpu_percent: 0.0, // Requires two samples with a delta — set to 0 for snapshot
                memory_bytes,
                memory_percent,
                open_fds,
                threads,
                cmdline,
            });
        }

        Ok(result)
    }

    fn listening_ports(&self) -> PlatformResult<Vec<ListeningPort>> {
        let mut result = Vec::new();

        for (path, protocol) in &[("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")] {
            let content = match fs::read_to_string(self.path(path)) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 {
                    continue;
                }

                // State 0x0A = LISTEN
                let state = match u8::from_str_radix(fields[3], 16) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if state != 0x0A {
                    continue;
                }

                let (bind_address, port) = match Self::parse_hex_addr_port(fields[1]) {
                    Some(v) => v,
                    None => continue,
                };

                // Inode is field 9
                let inode: u64 = match fields[9].parse() {
                    Ok(i) => i,
                    Err(_) => continue,
                };

                let (pid, process_name) =
                    self.find_pid_for_inode(inode).unwrap_or((0, String::new()));

                result.push(ListeningPort {
                    port,
                    protocol: protocol.to_string(),
                    pid,
                    process_name,
                    bind_address,
                });
            }
        }

        Ok(result)
    }

    fn network_interfaces(&self) -> PlatformResult<Vec<NetworkInterface>> {
        let sys_net = fs::read_dir(self.path("/sys/class/net")).map_err(PlatformError::Io)?;
        let mut result = Vec::new();

        for entry in sys_net.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip loopback
            if name == "lo" {
                continue;
            }

            // Check operstate — skip interfaces that are down
            let operstate_path = format!("/sys/class/net/{}/operstate", name);
            let operstate = fs::read_to_string(self.path(&operstate_path))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            if operstate == "down" {
                continue;
            }

            // MAC address
            let mac_path = format!("/sys/class/net/{}/address", name);
            let mac = fs::read_to_string(self.path(&mac_path))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            // MTU
            let mtu_path = format!("/sys/class/net/{}/mtu", name);
            let mtu = fs::read_to_string(self.path(&mtu_path))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(0);

            // IP addresses — parse from /proc/net/if_inet6 and ip command output
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();

            // Read IPv4 from /proc/net/fib_trie is complex; use ip command as fallback
            if let Ok(output) = self
                .command("ip")
                .args(["-4", "addr", "show", &name])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("inet ") {
                        if let Some(addr) = trimmed.split_whitespace().nth(1) {
                            // addr is like "192.168.1.100/24" — strip the prefix length
                            let ip = addr.split('/').next().unwrap_or(addr);
                            ipv4.push(ip.to_string());
                        }
                    }
                }
            }

            if let Ok(output) = self
                .command("ip")
                .args(["-6", "addr", "show", &name])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("inet6 ") {
                        if let Some(addr) = trimmed.split_whitespace().nth(1) {
                            let ip = addr.split('/').next().unwrap_or(addr);
                            // Skip link-local addresses (fe80::)
                            if !ip.starts_with("fe80:") {
                                ipv6.push(ip.to_string());
                            }
                        }
                    }
                }
            }

            result.push(NetworkInterface {
                name,
                mac,
                ipv4,
                ipv6,
                mtu,
            });
        }

        Ok(result)
    }

    fn cloud_info(&self) -> PlatformResult<Option<CloudInfo>> {
        // Try AWS IMDSv2 first: get a token, then query metadata.
        // We use curl with a 2s timeout since this is a sync method and we cannot
        // use async HTTP. If curl is unavailable or the host is not on a cloud
        // provider, we return None gracefully.

        // AWS IMDSv2
        if let Some(info) = self.try_aws_imdsv2() {
            return Ok(Some(info));
        }

        // GCP metadata
        if let Some(info) = self.try_gcp_metadata() {
            return Ok(Some(info));
        }

        // Azure IMDS
        if let Some(info) = self.try_azure_imds() {
            return Ok(Some(info));
        }

        Ok(None)
    }

    fn packages(&self) -> PlatformResult<Vec<PackageInfo>> {
        let mut result = Vec::new();

        // Try dpkg (Debian/Ubuntu)
        if let Ok(output) = self
            .command("dpkg-query")
            .args(["-W", "-f", "${Package}\t${Version}\n"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.splitn(2, '\t').collect();
                    if parts.len() == 2 {
                        result.push(PackageInfo {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            manager: "dpkg".to_string(),
                        });
                    }
                }
                if !result.is_empty() {
                    return Ok(result);
                }
            }
        }

        // Try rpm (RHEL/CentOS/Fedora)
        if let Ok(output) = self
            .command("rpm")
            .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.splitn(2, '\t').collect();
                    if parts.len() == 2 {
                        result.push(PackageInfo {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            manager: "rpm".to_string(),
                        });
                    }
                }
                if !result.is_empty() {
                    return Ok(result);
                }
            }
        }

        // Try apk (Alpine)
        if let Ok(output) = self.command("apk").args(["list", "--installed"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // Format: "name-version-rrelease arch {origin} (license)"
                    // We split at the first space and then separate name/version at the last dash
                    let pkg_part = line.split_whitespace().next().unwrap_or("");
                    if let Some(last_dash) = pkg_part.rfind('-') {
                        if let Some(second_last) = pkg_part[..last_dash].rfind('-') {
                            result.push(PackageInfo {
                                name: pkg_part[..second_last].to_string(),
                                version: pkg_part[second_last + 1..].to_string(),
                                manager: "apk".to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    fn services(&self) -> PlatformResult<Vec<ServiceInfo>> {
        let mut result = Vec::new();

        let output = match self
            .command("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--all",
                "--no-pager",
                "--no-legend",
                "--plain",
            ])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return Ok(result), // systemctl not available
        };

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Fields: UNIT LOAD ACTIVE SUB DESCRIPTION...
            if fields.len() < 4 {
                continue;
            }

            let unit_name = fields[0].trim_end_matches(".service").to_string();
            let active = fields[2]; // "active" or "inactive" or "failed"
            let sub = fields[3]; // "running", "dead", "exited", etc.

            let status = format!("{}/{}", active, sub);

            // Check if enabled
            let enabled = self
                .command("systemctl")
                .args(["is-enabled", fields[0]])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .eq_ignore_ascii_case("enabled")
                })
                .unwrap_or(false);

            result.push(ServiceInfo {
                name: unit_name,
                status,
                enabled,
            });
        }

        Ok(result)
    }

    fn users(&self) -> PlatformResult<Vec<UserInfo>> {
        // Read /etc/passwd — NEVER read /etc/shadow
        let content = fs::read_to_string(self.path("/etc/passwd")).map_err(PlatformError::Io)?;

        // Read group file to build gid-to-group mapping and user-to-groups mapping
        let group_content = fs::read_to_string(self.path("/etc/group")).unwrap_or_default();
        let mut gid_to_group: HashMap<u32, String> = HashMap::new();
        let mut user_groups: HashMap<String, Vec<String>> = HashMap::new();

        for line in group_content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 4 {
                continue;
            }
            let group_name = fields[0].to_string();
            if let Ok(gid) = fields[2].parse::<u32>() {
                gid_to_group.insert(gid, group_name.clone());
            }
            // Field 3 is comma-separated list of member usernames
            if !fields[3].is_empty() {
                for member in fields[3].split(',') {
                    let member = member.trim();
                    if !member.is_empty() {
                        user_groups
                            .entry(member.to_string())
                            .or_default()
                            .push(group_name.clone());
                    }
                }
            }
        }

        let mut result = Vec::new();

        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            // /etc/passwd format: username:x:uid:gid:gecos:home:shell
            if fields.len() < 7 {
                continue;
            }

            let username = fields[0].to_string();
            let uid = match fields[2].parse::<u32>() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let gid = fields[3].parse::<u32>().unwrap_or(0);
            let shell = fields[6].to_string();

            // Primary group
            let mut groups = Vec::new();
            if let Some(primary_group) = gid_to_group.get(&gid) {
                groups.push(primary_group.clone());
            }

            // Supplementary groups
            if let Some(supplementary) = user_groups.get(&username) {
                for g in supplementary {
                    if !groups.contains(g) {
                        groups.push(g.clone());
                    }
                }
            }

            result.push(UserInfo {
                username,
                uid,
                groups,
                shell,
            });
        }

        Ok(result)
    }

    fn cgroup_cpu(&self) -> PlatformResult<Option<CgroupCpuInfo>> {
        // Read cgroup v2 cpu.max and cpu.stat
        // cpu.max format: "$MAX $PERIOD" or "max $PERIOD"
        let cpu_max = match fs::read_to_string(self.path("/sys/fs/cgroup/cpu.max")) {
            Ok(c) => c,
            Err(_) => return Ok(None), // cgroup v2 not available
        };

        let fields: Vec<&str> = cpu_max.split_whitespace().collect();
        if fields.len() < 2 {
            return Ok(None);
        }

        let has_limit = fields[0] != "max";
        let limit_cores = if has_limit {
            let max_us: f64 = fields[0].parse().unwrap_or(0.0);
            let period_us: f64 = fields[1].parse().unwrap_or(100_000.0);
            if period_us > 0.0 {
                max_us / period_us
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Read usage from cpu.stat
        let usage_ns = fs::read_to_string(self.path("/sys/fs/cgroup/cpu.stat"))
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("usage_usec"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|usec| usec * 1000) // convert to nanoseconds
            })
            .unwrap_or(0);

        Ok(Some(CgroupCpuInfo {
            has_limit,
            limit_cores,
            usage_ns,
        }))
    }

    fn cgroup_memory(&self) -> PlatformResult<Option<CgroupMemoryInfo>> {
        // Read cgroup v2 memory.max and memory.current
        let memory_max_str = match fs::read_to_string(self.path("/sys/fs/cgroup/memory.max")) {
            Ok(c) => c.trim().to_string(),
            Err(_) => return Ok(None), // cgroup v2 not available
        };

        let has_limit = memory_max_str != "max";
        let limit_bytes = if has_limit {
            memory_max_str.parse::<u64>().unwrap_or(0)
        } else {
            0
        };

        let usage_bytes = fs::read_to_string(self.path("/sys/fs/cgroup/memory.current"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        Ok(Some(CgroupMemoryInfo {
            has_limit,
            limit_bytes,
            usage_bytes,
        }))
    }

    fn file_hash(&self, path: &str) -> PlatformResult<String> {
        let content = fs::read(path).map_err(PlatformError::Io)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();
        Ok(format!("{:x}", hash))
    }

    fn read_file_string(&self, path: &str) -> PlatformResult<String> {
        fs::read_to_string(path).map_err(PlatformError::Io)
    }
}

// --- Cloud metadata helpers (private) ---

impl LinuxPlatform {
    /// Try AWS IMDSv2: first get a session token, then query instance metadata.
    fn try_aws_imdsv2(&self) -> Option<CloudInfo> {
        // Step 1: Get IMDSv2 token
        let token_output = self
            .command("curl")
            .args([
                "-s",
                "--max-time",
                "2",
                "-X",
                "PUT",
                "http://169.254.169.254/latest/api/token",
                "-H",
                "X-aws-ec2-metadata-token-ttl-seconds: 60",
            ])
            .output()
            .ok()?;

        if !token_output.status.success() {
            return None;
        }

        let token = String::from_utf8_lossy(&token_output.stdout)
            .trim()
            .to_string();
        if token.is_empty() {
            return None;
        }

        let fetch = |path: &str| -> String {
            self.command("curl")
                .args([
                    "-s",
                    "--max-time",
                    "2",
                    "-H",
                    &format!("X-aws-ec2-metadata-token: {}", token),
                    &format!("http://169.254.169.254/latest/meta-data/{}", path),
                ])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        };

        let instance_id = fetch("instance-id");
        if instance_id.is_empty() || instance_id.contains("Not Found") {
            return None;
        }

        Some(CloudInfo {
            provider: "aws".to_string(),
            region: fetch("placement/region"),
            instance_type: fetch("instance-type"),
            instance_id,
            vpc_id: fetch("network/interfaces/macs/")
                .lines()
                .next()
                .map(|mac| fetch(&format!("network/interfaces/macs/{}vpc-id", mac)))
                .unwrap_or_default(),
        })
    }

    /// Try GCP metadata server.
    fn try_gcp_metadata(&self) -> Option<CloudInfo> {
        let fetch = |path: &str| -> Option<String> {
            self.command("curl")
                .args([
                    "-s",
                    "--max-time",
                    "2",
                    "-H",
                    "Metadata-Flavor: Google",
                    &format!(
                        "http://metadata.google.internal/computeMetadata/v1/{}",
                        path
                    ),
                ])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        };

        let instance_id = fetch("instance/id")?;

        // Zone is like "projects/123/zones/us-central1-a", extract region
        let zone = fetch("instance/zone").unwrap_or_default();
        let region = zone
            .rsplit('/')
            .next()
            .and_then(|z| z.rsplitn(2, '-').last())
            .unwrap_or("")
            .to_string();

        Some(CloudInfo {
            provider: "gcp".to_string(),
            region,
            instance_type: fetch("instance/machine-type")
                .and_then(|mt| mt.rsplit('/').next().map(|s| s.to_string()))
                .unwrap_or_default(),
            instance_id,
            vpc_id: fetch("instance/network-interfaces/0/network")
                .and_then(|n| n.rsplit('/').next().map(|s| s.to_string()))
                .unwrap_or_default(),
        })
    }

    /// Try Azure IMDS.
    fn try_azure_imds(&self) -> Option<CloudInfo> {
        let output = self
            .command("curl")
            .args([
                "-s",
                "--max-time",
                "2",
                "-H",
                "Metadata: true",
                "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let body = String::from_utf8_lossy(&output.stdout).to_string();

        let body: serde_json::Value = serde_json::from_str(&body).ok()?;
        let extract = |key: &str| -> String {
            body.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };

        let vm_id = extract("vmId");
        if vm_id.is_empty() {
            return None;
        }

        Some(CloudInfo {
            provider: "azure".to_string(),
            region: extract("location"),
            instance_type: extract("vmSize"),
            instance_id: vm_id,
            vpc_id: extract("virtualMachineScaleSetId"),
        })
    }
}

#[cfg(test)]
mod tests;
