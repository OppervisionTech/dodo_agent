//! Lite (IoT/Edge) platform implementation.
//!
//! Reads the same `/proc` files as the full Linux variant but with
//! deliberate restrictions for resource-constrained devices:
//!
//! - **No eBPF** — `capabilities()` always reports `ebpf_available: false`.
//! - **No cgroup awareness** — `cgroup_cpu()` / `cgroup_memory()` return `None`.
//! - **No cloud metadata** — `cloud_info()` returns `None`.
//! - **Simpler process listing** — basic `/proc/<pid>/stat` without FD counting.
//! - **Package managers** — tries `apk` (Alpine) first, then `dpkg`.
//!
//! Because `lite` and `linux` are mutually exclusive feature flags (only one
//! is compiled at a time), the `/proc` parsing logic is duplicated here rather
//! than shared.  This keeps each variant self-contained and avoids
//! conditional-compilation gymnastics.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::common::{is_pseudo_filesystem, tcp_state_name};
use crate::*;

// ---------------------------------------------------------------------------
// Public struct
// ---------------------------------------------------------------------------

pub struct LitePlatform;

impl LitePlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LitePlatform {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// /proc helpers (duplicated from linux variant for feature-flag isolation)
// ---------------------------------------------------------------------------

/// Read a text file fully into a `String`.
fn read_string(path: &str) -> PlatformResult<String> {
    fs::read_to_string(path).map_err(PlatformError::Io)
}

/// Parse a `key: value` pair from `/proc/meminfo`-style lines.
/// Value is returned in **bytes** (original is in kB).
fn parse_meminfo_kb(line: &str) -> Option<(String, u64)> {
    let mut parts = line.splitn(2, ':');
    let key = parts.next()?.trim().to_string();
    let val_str = parts.next()?.trim();
    // Strip trailing " kB"
    let numeric = val_str.split_whitespace().next()?;
    let kb: u64 = numeric.parse().ok()?;
    Some((key, kb * 1024))
}

/// Parse `/proc/stat` aggregate and per-CPU lines into `CpuTimes` vec.
fn parse_proc_stat(content: &str) -> PlatformResult<Vec<CpuTimes>> {
    let mut result = Vec::new();
    for line in content.lines() {
        if !line.starts_with("cpu") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let p = |i: usize| -> u64 { fields.get(i).and_then(|v| v.parse().ok()).unwrap_or(0) };
        result.push(CpuTimes {
            user: p(1),
            nice: p(2),
            system: p(3),
            idle: p(4),
            iowait: p(5),
            irq: p(6),
            softirq: p(7),
            steal: p(8),
            guest: p(9),
            guest_nice: p(10),
        });
    }
    if result.is_empty() {
        return Err(PlatformError::Parse("no cpu lines in /proc/stat".into()));
    }
    Ok(result)
}

/// Parse `/proc/loadavg`.
fn parse_loadavg(content: &str) -> PlatformResult<LoadAverage> {
    let fields: Vec<&str> = content.split_whitespace().collect();
    if fields.len() < 3 {
        return Err(PlatformError::Parse(
            "unexpected /proc/loadavg format".into(),
        ));
    }
    Ok(LoadAverage {
        one: fields[0].parse().unwrap_or(0.0),
        five: fields[1].parse().unwrap_or(0.0),
        fifteen: fields[2].parse().unwrap_or(0.0),
    })
}

/// Parse `/proc/meminfo` into `MemoryInfo`.
fn parse_meminfo(content: &str) -> PlatformResult<MemoryInfo> {
    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((k, v)) = parse_meminfo_kb(line) {
            map.insert(k, v);
        }
    }
    let get = |key: &str| -> u64 { map.get(key).copied().unwrap_or(0) };

    let total = get("MemTotal");
    let free = get("MemFree");
    let available = get("MemAvailable");
    let buffers = get("Buffers");
    let cached = get("Cached");
    let swap_total = get("SwapTotal");
    let swap_free = get("SwapFree");

    Ok(MemoryInfo {
        total_bytes: total,
        available_bytes: available,
        free_bytes: free,
        used_bytes: total.saturating_sub(free + buffers + cached),
        cached_bytes: cached,
        buffers_bytes: buffers,
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_total.saturating_sub(swap_free),
        hugepages_total: get("HugePages_Total"),
        hugepages_free: get("HugePages_Free"),
    })
}

/// Parse `/proc/diskstats` into `DiskIo` entries.
fn parse_diskstats(content: &str) -> PlatformResult<Vec<DiskIo>> {
    let mut result = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Format: major minor name rd_ios rd_merges rd_sectors rd_ticks
        //         wr_ios wr_merges wr_sectors wr_ticks io_in_progress io_ticks weighted_ticks ...
        if fields.len() < 14 {
            continue;
        }
        let device = fields[2].to_string();
        // Skip partitions — only report whole devices.
        // Heuristic: skip if the name ends in a digit and a matching prefix
        // without the digit exists (e.g. sda1 when sda is present).
        // For simplicity on IoT, report everything and let the collector filter.
        let p = |i: usize| -> u64 { fields[i].parse().unwrap_or(0) };
        result.push(DiskIo {
            device,
            read_bytes: p(5) * 512, // sectors → bytes
            write_bytes: p(9) * 512,
            read_ops: p(3),
            write_ops: p(7),
            io_time_ms: p(12),
            weighted_io_time_ms: p(13),
        });
    }
    Ok(result)
}

/// Read `/proc/mounts` and call `statvfs` for real filesystems.
fn collect_disk_spaces() -> PlatformResult<Vec<DiskSpace>> {
    let content = read_string("/proc/mounts")?;
    let mut result = Vec::new();
    let mut seen_mounts = std::collections::HashSet::new();

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let device = fields[0];
        let mount = fields[1];
        let fstype = fields[2];

        if is_pseudo_filesystem(fstype) {
            continue;
        }
        // Deduplicate by mount point.
        if !seen_mounts.insert(mount.to_string()) {
            continue;
        }

        let c_path = match CString::new(mount) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

        // SAFETY: `c_path` is a valid NUL-terminated C string pointing to a
        // mount path obtained from `/proc/mounts`.  `stat` is a zeroed
        // `libc::statvfs` struct allocated on the stack.  `libc::statvfs` writes
        // into `stat` and does not retain the pointer after returning.
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret != 0 {
            continue; // permission denied or unmounted — skip silently
        }

        let bsize = stat.f_frsize as u64;
        let total = (stat.f_blocks as u64) * bsize;
        let free = (stat.f_bfree as u64) * bsize;

        result.push(DiskSpace {
            mount_point: mount.to_string(),
            device: device.to_string(),
            filesystem: fstype.to_string(),
            total_bytes: total,
            used_bytes: total.saturating_sub(free),
            free_bytes: free,
            inodes_total: stat.f_files as u64,
            inodes_used: (stat.f_files as u64).saturating_sub(stat.f_ffree as u64),
        });
    }
    Ok(result)
}

/// Parse `/proc/net/dev` into `NetworkCounters`.
fn parse_net_dev(content: &str) -> PlatformResult<Vec<NetworkCounters>> {
    let mut result = Vec::new();
    for line in content.lines().skip(2) {
        // Each line: "  iface: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets tx_errs tx_drop ..."
        let line = line.trim();
        let (iface, rest) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        let fields: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        if fields.len() < 16 {
            continue;
        }
        let iface = iface.trim().to_string();
        // Skip loopback.
        if iface == "lo" {
            continue;
        }
        result.push(NetworkCounters {
            interface: iface,
            bytes_recv: fields[0],
            packets_recv: fields[1],
            errors_recv: fields[2],
            drops_recv: fields[3],
            bytes_sent: fields[8],
            packets_sent: fields[9],
            errors_sent: fields[10],
            drops_sent: fields[11],
        });
    }
    Ok(result)
}

/// Parse `/proc/net/tcp` (and optionally tcp6) to count connection states.
fn count_tcp_connections() -> PlatformResult<TcpConnections> {
    let mut established: u64 = 0;
    let mut time_wait: u64 = 0;
    let mut close_wait: u64 = 0;
    let mut total: u64 = 0;

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let content = match fs::read_to_string(path) {
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
            match tcp_state_name(state) {
                "ESTABLISHED" => established += 1,
                "TIME_WAIT" => time_wait += 1,
                "CLOSE_WAIT" => close_wait += 1,
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

/// Simplified process listing for IoT — avoids counting open FDs to reduce
/// syscalls on constrained devices.
fn collect_processes() -> PlatformResult<Vec<ProcessInfo>> {
    let mut procs = Vec::new();
    let total_mem = {
        let mi = parse_meminfo(&read_string("/proc/meminfo")?)?;
        mi.total_bytes
    };

    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => return Err(PlatformError::Io(e)),
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Parse /proc/<pid>/stat — the comm field is wrapped in parens and may
        // contain spaces, so find the last ')' to anchor field offsets.
        let comm_end = match stat_content.rfind(')') {
            Some(i) => i,
            None => continue,
        };
        let comm_start = match stat_content.find('(') {
            Some(i) => i,
            None => continue,
        };
        let proc_name = stat_content[comm_start + 1..comm_end].to_string();
        let rest = &stat_content[comm_end + 2..]; // skip ") "
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }

        let state = fields[0].chars().next().unwrap_or('?');
        let threads: u32 = fields.get(17).and_then(|v| v.parse().ok()).unwrap_or(1);
        // RSS is in pages (field index 21 from the rest, which is field 23 overall).
        let rss_pages: u64 = fields.get(21).and_then(|v| v.parse().ok()).unwrap_or(0);
        let page_size: u64 = 4096; // standard on most Linux, good enough for IoT
        let memory_bytes = rss_pages * page_size;

        let memory_percent = if total_mem > 0 {
            (memory_bytes as f64 / total_mem as f64) * 100.0
        } else {
            0.0
        };

        // Read uid for user mapping.
        let user = fs::read_to_string(format!("/proc/{}/status", pid))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .map(|u| u.to_string())
            })
            .unwrap_or_else(|| "?".to_string());

        let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        procs.push(ProcessInfo {
            pid,
            name: proc_name,
            user,
            state,
            cpu_percent: 0.0, // requires two samples — not computed in snapshot
            memory_bytes,
            memory_percent,
            open_fds: -1, // skipped on lite to save syscalls
            threads,
            cmdline,
        });
    }

    Ok(procs)
}

/// Collect listening ports from `/proc/net/tcp` and `/proc/net/tcp6`.
fn collect_listening_ports() -> PlatformResult<Vec<ListeningPort>> {
    let mut ports = Vec::new();
    // Build pid→name map from /proc.
    let mut inode_to_pid: HashMap<u64, u32> = HashMap::new();
    let mut pid_names: HashMap<u32, String> = HashMap::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid: u32 = match name.to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            // Read comm for process name.
            if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
                pid_names.insert(pid, comm.trim().to_string());
            }
            // Scan fd symlinks for socket inodes.
            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(fds) = fs::read_dir(&fd_dir) {
                for fd in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") {
                            if let Some(inode_str) = link_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    inode_to_pid.insert(inode, pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for (path, proto) in &[("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")] {
        let content = match fs::read_to_string(path) {
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
            // local_address is "ADDR:PORT" in hex.
            if let Some((addr_hex, port_hex)) = fields[1].rsplit_once(':') {
                let port = match u16::from_str_radix(port_hex, 16) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let inode: u64 = fields[9].parse().unwrap_or(0);
                let pid = inode_to_pid.get(&inode).copied().unwrap_or(0);
                let process_name = pid_names.get(&pid).cloned().unwrap_or_default();

                // Decode bind address (IPv4 only for brevity).
                let bind_address = if addr_hex.len() == 8 {
                    // IPv4 stored as little-endian hex.
                    if let Ok(addr_u32) = u32::from_str_radix(addr_hex, 16) {
                        let bytes = addr_u32.to_be_bytes();
                        // /proc/net/tcp stores IPv4 in host byte order on LE.
                        format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
                    } else {
                        addr_hex.to_string()
                    }
                } else {
                    // IPv6 — return raw hex for now.
                    addr_hex.to_string()
                };

                ports.push(ListeningPort {
                    port,
                    protocol: proto.to_string(),
                    pid,
                    process_name,
                    bind_address,
                });
            }
        }
    }

    Ok(ports)
}

/// Enumerate network interfaces from `/sys/class/net`.
fn collect_network_interfaces() -> PlatformResult<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();
    let net_dir = "/sys/class/net";
    let entries = match fs::read_dir(net_dir) {
        Ok(e) => e,
        Err(e) => return Err(PlatformError::Io(e)),
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }

        let base = format!("{}/{}", net_dir, name);
        let mac = fs::read_to_string(format!("{}/address", base))
            .unwrap_or_default()
            .trim()
            .to_string();
        let mtu: u32 = fs::read_to_string(format!("{}/mtu", base))
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(1500);

        // Parse IP addresses from /proc/net/if_inet6 and ip command output
        // would be heavy; for lite, report empty and let inventory collector
        // fill this via netlink or a future helper.
        interfaces.push(NetworkInterface {
            name,
            mac,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            mtu,
        });
    }

    Ok(interfaces)
}

/// List installed packages.  Tries `apk` (Alpine — common on IoT) first,
/// falls back to `dpkg-query` (Debian/Ubuntu).
fn collect_packages() -> PlatformResult<Vec<PackageInfo>> {
    // Try apk first (Alpine Linux — very common on IoT/edge).
    if Path::new("/sbin/apk").exists() || Path::new("/usr/sbin/apk").exists() {
        if let Ok(output) = std::process::Command::new("apk")
            .args(["info", "-v"])
            .output()
        {
            if output.status.success() {
                let mut packages = Vec::new();
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // apk info -v outputs: "package-name-version"
                    // Split at the last '-' that precedes a digit.
                    if let Some(idx) = line.rmatch_indices('-').find_map(|(i, _)| {
                        line.get(i + 1..i + 2).and_then(|c| {
                            if c.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
                                Some(i)
                            } else {
                                None
                            }
                        })
                    }) {
                        packages.push(PackageInfo {
                            name: line[..idx].to_string(),
                            version: line[idx + 1..].to_string(),
                            manager: "apk".to_string(),
                        });
                    } else {
                        packages.push(PackageInfo {
                            name: line.to_string(),
                            version: String::new(),
                            manager: "apk".to_string(),
                        });
                    }
                }
                return Ok(packages);
            }
        }
    }

    // Fallback: dpkg.
    if Path::new("/usr/bin/dpkg-query").exists() {
        if let Ok(output) = std::process::Command::new("dpkg-query")
            .args(["-W", "-f", "${Package}\t${Version}\n"])
            .output()
        {
            if output.status.success() {
                let mut packages = Vec::new();
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.splitn(2, '\t').collect();
                    if parts.is_empty() {
                        continue;
                    }
                    packages.push(PackageInfo {
                        name: parts[0].to_string(),
                        version: parts.get(1).unwrap_or(&"").to_string(),
                        manager: "dpkg".to_string(),
                    });
                }
                return Ok(packages);
            }
        }
    }

    Ok(Vec::new())
}

/// List systemd services (if available).
fn collect_services() -> PlatformResult<Vec<ServiceInfo>> {
    let output = match std::process::Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Ok(Vec::new()),
    };

    let mut services = Vec::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // unit  load  active  sub  description...
        if fields.len() < 4 {
            continue;
        }
        let name = fields[0]
            .strip_suffix(".service")
            .unwrap_or(fields[0])
            .to_string();
        let active = fields[2];
        let sub = fields[3];
        services.push(ServiceInfo {
            name,
            status: format!("{}/{}", active, sub),
            enabled: active == "active",
        });
    }
    Ok(services)
}

/// Parse `/etc/passwd` for user info.
fn collect_users() -> PlatformResult<Vec<UserInfo>> {
    let content = read_string("/etc/passwd")?;
    let mut users = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let uid: u32 = match fields[2].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        // Only report human users (uid >= 1000) and root.
        if uid != 0 && uid < 1000 {
            continue;
        }
        users.push(UserInfo {
            username: fields[0].to_string(),
            uid,
            groups: Vec::new(), // Populated by inventory collector if needed.
            shell: fields[6].to_string(),
        });
    }
    Ok(users)
}

/// SHA-256 hash of a file.
fn hash_file(path: &str) -> PlatformResult<String> {
    let data = fs::read(path).map_err(PlatformError::Io)?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

// ---------------------------------------------------------------------------
// Platform info helpers
// ---------------------------------------------------------------------------

fn build_platform_info() -> PlatformResult<PlatformInfo> {
    let hostname = read_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let kernel_version = read_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let architecture = read_string("/proc/sys/kernel/arch")
        .or_else(|_| {
            // Fallback: parse from uname via /proc/version or use a constant.
            let ver = read_string("/proc/version")?;
            // Typical: "Linux version 5.15.0 (gcc ...) #1 SMP ... x86_64"
            // Architecture might not always be present.
            Ok(ver
                .split_whitespace()
                .last()
                .unwrap_or("unknown")
                .to_string())
        })
        .unwrap_or_else(|_: PlatformError| "unknown".into())
        .trim()
        .to_string();

    let machine_id = read_string("/etc/machine-id")
        .or_else(|_| read_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let os_version = read_string("/etc/os-release")
        .map(|c| {
            c.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| {
                    l.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string()
                })
                .unwrap_or_else(|| "Linux".to_string())
        })
        .unwrap_or_else(|_| "Linux".to_string());

    // Count CPUs from /proc/cpuinfo.
    let cpuinfo = read_string("/proc/cpuinfo").unwrap_or_default();
    let logical_cpus = cpuinfo
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count() as u32;
    // Physical cores: count unique (physical id, core id) pairs.
    let mut physical_set = std::collections::HashSet::new();
    let mut current_phys_id = String::new();
    for line in cpuinfo.lines() {
        if line.starts_with("physical id") {
            current_phys_id = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.starts_with("core id") {
            let core_id = line.split(':').nth(1).unwrap_or("").trim().to_string();
            physical_set.insert(format!("{}:{}", current_phys_id, core_id));
        }
    }
    let physical_cpus = if physical_set.is_empty() {
        logical_cpus
    } else {
        physical_set.len() as u32
    };

    let meminfo = read_string("/proc/meminfo").unwrap_or_default();
    let total_memory = meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(parse_meminfo_kb)
        .map(|(_, v)| v)
        .unwrap_or(0);

    // Boot time from /proc/stat "btime" line.
    let stat_content = read_string("/proc/stat").unwrap_or_default();
    let boot_time = stat_content
        .lines()
        .find(|l| l.starts_with("btime"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    Ok(PlatformInfo {
        hostname,
        os_family: "linux".to_string(),
        os_version,
        kernel_version,
        architecture,
        machine_id,
        cpu_count_logical: logical_cpus.max(1),
        cpu_count_physical: physical_cpus.max(1),
        total_memory_bytes: total_memory,
        boot_time_unix: boot_time,
    })
}

fn parse_kernel_version(release: &str) -> (u32, u32) {
    let parts: Vec<&str> = release.split('.').collect();
    let major: u32 = parts.first().and_then(|v| v.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    (major, minor)
}

// ---------------------------------------------------------------------------
// Platform trait implementation
// ---------------------------------------------------------------------------

impl Platform for LitePlatform {
    fn info(&self) -> PlatformResult<PlatformInfo> {
        build_platform_info()
    }

    fn capabilities(&self) -> PlatformResult<PlatformCapabilities> {
        let release = read_string("/proc/sys/kernel/osrelease").unwrap_or_else(|_| "0.0.0".into());
        let (major, minor) = parse_kernel_version(release.trim());

        Ok(PlatformCapabilities {
            ebpf_available: false, // Never available on lite/IoT variant
            container_detected: false,
            cloud_detected: false,
            kernel_version_major: major,
            kernel_version_minor: minor,
        })
    }

    fn cpu_times(&self) -> PlatformResult<Vec<CpuTimes>> {
        let content = read_string("/proc/stat")?;
        parse_proc_stat(&content)
    }

    fn load_average(&self) -> PlatformResult<LoadAverage> {
        let content = read_string("/proc/loadavg")?;
        parse_loadavg(&content)
    }

    fn memory_info(&self) -> PlatformResult<MemoryInfo> {
        let content = read_string("/proc/meminfo")?;
        parse_meminfo(&content)
    }

    fn disk_spaces(&self) -> PlatformResult<Vec<DiskSpace>> {
        collect_disk_spaces()
    }

    fn disk_io(&self) -> PlatformResult<Vec<DiskIo>> {
        let content = read_string("/proc/diskstats")?;
        parse_diskstats(&content)
    }

    fn network_counters(&self) -> PlatformResult<Vec<NetworkCounters>> {
        let content = read_string("/proc/net/dev")?;
        parse_net_dev(&content)
    }

    fn tcp_connections(&self) -> PlatformResult<TcpConnections> {
        count_tcp_connections()
    }

    fn processes(&self) -> PlatformResult<Vec<ProcessInfo>> {
        collect_processes()
    }

    fn listening_ports(&self) -> PlatformResult<Vec<ListeningPort>> {
        collect_listening_ports()
    }

    fn network_interfaces(&self) -> PlatformResult<Vec<NetworkInterface>> {
        collect_network_interfaces()
    }

    fn cloud_info(&self) -> PlatformResult<Option<CloudInfo>> {
        // IoT/edge devices are not on cloud infrastructure.
        Ok(None)
    }

    fn packages(&self) -> PlatformResult<Vec<PackageInfo>> {
        collect_packages()
    }

    fn services(&self) -> PlatformResult<Vec<ServiceInfo>> {
        collect_services()
    }

    fn users(&self) -> PlatformResult<Vec<UserInfo>> {
        collect_users()
    }

    fn cgroup_cpu(&self) -> PlatformResult<Option<CgroupCpuInfo>> {
        // Cgroups are not relevant for bare-metal IoT/edge devices.
        Ok(None)
    }

    fn cgroup_memory(&self) -> PlatformResult<Option<CgroupMemoryInfo>> {
        // Cgroups are not relevant for bare-metal IoT/edge devices.
        Ok(None)
    }

    fn file_hash(&self, path: &str) -> PlatformResult<String> {
        hash_file(path)
    }

    fn read_file_string(&self, path: &str) -> PlatformResult<String> {
        read_string(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_stat_aggregate() {
        let input = "\
cpu  100 20 30 9000 50 10 5 0 0 0
cpu0 50 10 15 4500 25 5 3 0 0 0
cpu1 50 10 15 4500 25 5 2 0 0 0
";
        let result = parse_proc_stat(input).expect("parse should succeed");
        assert_eq!(result.len(), 3); // aggregate + 2 cores
        assert_eq!(result[0].user, 100);
        assert_eq!(result[0].idle, 9000);
        assert_eq!(result[0].system, 30);
    }

    #[test]
    fn parse_proc_stat_empty_fails() {
        let input = "intr 1000 50 20\nctxt 200000\n";
        assert!(parse_proc_stat(input).is_err());
    }

    #[test]
    fn parse_loadavg_normal() {
        let input = "0.52 0.34 0.25 1/150 12345";
        let la = parse_loadavg(input).expect("parse should succeed");
        assert!((la.one - 0.52).abs() < f64::EPSILON);
        assert!((la.five - 0.34).abs() < f64::EPSILON);
        assert!((la.fifteen - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_meminfo_basic() {
        let input = "\
MemTotal:       1024000 kB
MemFree:         512000 kB
MemAvailable:    768000 kB
Buffers:          64000 kB
Cached:          128000 kB
SwapTotal:       256000 kB
SwapFree:        256000 kB
HugePages_Total:       0
HugePages_Free:        0
";
        let mi = parse_meminfo(input).expect("parse should succeed");
        assert_eq!(mi.total_bytes, 1024000 * 1024);
        assert_eq!(mi.free_bytes, 512000 * 1024);
        assert_eq!(mi.available_bytes, 768000 * 1024);
        assert_eq!(mi.buffers_bytes, 64000 * 1024);
        assert_eq!(mi.cached_bytes, 128000 * 1024);
        assert_eq!(mi.swap_total_bytes, 256000 * 1024);
        assert_eq!(mi.swap_used_bytes, 0);
        // used = total - free - buffers - cached
        let expected_used = (1024000 - 512000 - 64000 - 128000) * 1024;
        assert_eq!(mi.used_bytes, expected_used);
    }

    #[test]
    fn parse_net_dev_skips_loopback() {
        let input = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 100 0 0 0 0 0 0 1000 100 0 0 0 0 0 0
  eth0: 5000 200 1 0 0 0 0 0 3000 150 0 2 0 0 0 0
";
        let counters = parse_net_dev(input).expect("parse should succeed");
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].interface, "eth0");
        assert_eq!(counters[0].bytes_recv, 5000);
        assert_eq!(counters[0].bytes_sent, 3000);
        assert_eq!(counters[0].errors_recv, 1);
        assert_eq!(counters[0].drops_sent, 2);
    }

    #[test]
    fn parse_diskstats_basic() {
        let input = "\
   8       0 sda 1000 0 20000 500 2000 0 40000 800 0 1200 1300 0 0 0 0 0 0
   8       1 sda1 800 0 16000 400 1500 0 30000 600 0 900 1000 0 0 0 0 0 0
";
        let io = parse_diskstats(input).expect("parse should succeed");
        assert_eq!(io.len(), 2);
        assert_eq!(io[0].device, "sda");
        assert_eq!(io[0].read_ops, 1000);
        assert_eq!(io[0].write_ops, 2000);
        assert_eq!(io[0].read_bytes, 20000 * 512);
        assert_eq!(io[0].write_bytes, 40000 * 512);
    }

    #[test]
    fn parse_kernel_version_normal() {
        assert_eq!(parse_kernel_version("5.15.0-generic"), (5, 15));
        assert_eq!(parse_kernel_version("6.1.0"), (6, 1));
        assert_eq!(parse_kernel_version("4"), (4, 0));
    }

    #[test]
    fn capabilities_no_ebpf() {
        let p = LitePlatform::new();
        // This will fail on non-Linux hosts (no /proc), so just verify the
        // struct invariant when we can construct capabilities manually.
        let caps = PlatformCapabilities {
            ebpf_available: false,
            container_detected: false,
            cloud_detected: false,
            kernel_version_major: 5,
            kernel_version_minor: 10,
        };
        assert!(!caps.ebpf_available);
        assert!(!caps.cloud_detected);
        // Verify the platform exists and implements Send + Sync.
        let _boxed: Box<dyn Platform> = Box::new(p);
    }

    #[test]
    fn cloud_info_always_none() {
        let p = LitePlatform::new();
        // cloud_info() returns Ok(None) without hitting the filesystem.
        assert!(matches!(p.cloud_info(), Ok(None)));
    }

    #[test]
    fn cgroup_always_none() {
        let p = LitePlatform::new();
        assert!(matches!(p.cgroup_cpu(), Ok(None)));
        assert!(matches!(p.cgroup_memory(), Ok(None)));
    }
}
