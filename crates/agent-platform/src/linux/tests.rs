use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

// Fixtures write fake executables and run them. With tests in parallel, a
// fork from one test can inherit another test's still-open write fd, and the
// exec then fails with ETXTBSY (the platform swallows it, so the test sees an
// empty result). Serialize fixture tests instead of retrying around it.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    root: PathBuf,
    platform: LinuxPlatform,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        // A failed test poisons the lock; the next test still runs.
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("dodo-proc-fixture-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("bin")).unwrap();
        let platform = LinuxPlatform {
            root: root.clone(),
            command_dir: Some(root.join("bin")),
        };
        Self {
            root,
            platform,
            _serial: serial,
        }
    }

    fn write(&self, path: &str, content: &str) {
        let path = self.platform.path(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn directory(&self, path: &str) {
        fs::create_dir_all(self.platform.path(path)).unwrap();
    }

    fn command(&self, program: &str, script: &str) {
        let path = self.root.join("bin").join(program);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{script}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn host(&self) {
        self.write("/proc/sys/kernel/hostname", "fixture-host\n");
        self.write("/proc/sys/kernel/osrelease", "6.8.1-test\n");
        self.write(
            "/etc/os-release",
            "NAME=Fixture\nPRETTY_NAME=\"Fixture Linux\"\n",
        );
        self.write("/etc/machine-id", "fixture-stable-machine\n");
        self.write("/proc/cpuinfo", "processor : 0\nphysical id : 0\ncore id : 0\n\nprocessor : 1\nphysical id : 0\ncore id : 0\n\nprocessor : 2\nphysical id : 1\ncore id : 0\n");
        self.write("/proc/meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\nBuffers: 50 kB\nCached: 250 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\nHugePages_Total: 8\nHugePages_Free: 3\ninvalid\nBroken: NaN kB\n");
        self.write(
            "/proc/stat",
            "cpu 10 2 3 40 5 6 7 8 9 10\ncpu0 1 2 3 4 5 6 7\nshort\nbtime 1700000000\n",
        );
        self.command("uname", "[ \"$*\" = '-m' ] || exit 1; printf 'x86_64\\n'");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn host_identity_counters_and_units_are_read_from_an_isolated_snapshot() {
    let f = Fixture::new();
    f.host();
    let info = f.platform.info().unwrap();
    assert_eq!(
        (
            info.hostname.as_str(),
            info.os_family.as_str(),
            info.os_version.as_str()
        ),
        ("fixture-host", "linux", "Fixture Linux")
    );
    assert_eq!((info.cpu_count_logical, info.cpu_count_physical), (3, 2));
    assert_eq!(info.architecture, "x86_64");
    assert_eq!(info.machine_id, "fixture-stable-machine");
    assert_eq!(
        (info.total_memory_bytes, info.boot_time_unix),
        (1_024_000, 1_700_000_000)
    );
    let cpu = f.platform.cpu_times().unwrap();
    assert_eq!(cpu.len(), 2);
    assert_eq!((cpu[0].total(), cpu[0].busy(), cpu[0].guest), (81, 36, 9));
    assert_eq!((cpu[1].steal, cpu[1].guest_nice), (0, 0));
    let memory = f.platform.memory_info().unwrap();
    assert_eq!(
        (
            memory.total_bytes,
            memory.used_bytes,
            memory.available_bytes
        ),
        (1_024_000, 614_400, 409_600)
    );
    assert_eq!(
        (memory.swap_total_bytes, memory.swap_used_bytes),
        (204_800, 51_200)
    );
    assert_eq!((memory.hugepages_total, memory.hugepages_free), (8, 3));
    f.write("/proc/loadavg", "1.25 2.5 3.75 1/22 123\n");
    let load = f.platform.load_average().unwrap();
    assert_eq!((load.one, load.five, load.fifteen), (1.25, 2.5, 3.75));
    f.write("/.dockerenv", "");
    f.write("/sys/class/dmi/id/sys_vendor", "Amazon EC2\n");
    let caps = f.platform.capabilities().unwrap();
    assert!(caps.ebpf_available && caps.container_detected && caps.cloud_detected);
    assert_eq!(
        (caps.kernel_version_major, caps.kernel_version_minor),
        (6, 8)
    );
}

#[test]
fn host_fallbacks_persist_identity_and_reject_incomplete_proc_data() {
    let f = Fixture::new();
    assert!(matches!(f.platform.info(), Err(PlatformError::Io(_))));
    f.host();
    fs::remove_file(f.platform.path("/etc/machine-id")).unwrap();
    f.write("/var/lib/dbus/machine-id", " dbus-id \n");
    assert_eq!(f.platform.info().unwrap().machine_id, "dbus-id");
    f.write("/var/lib/dbus/machine-id", "\n");
    let generated = f.platform.info().unwrap().machine_id;
    assert!(uuid::Uuid::parse_str(&generated).is_ok());
    assert_eq!(f.platform.info().unwrap().machine_id, generated);
    fs::remove_file(f.platform.path("/etc/os-release")).unwrap();
    fs::remove_file(f.root.join("bin/uname")).unwrap();
    f.write("/proc/cpuinfo", "processor : 0\nprocessor : 1\n");
    let info = f.platform.info().unwrap();
    assert_eq!(
        (
            info.os_version.as_str(),
            info.architecture.as_str(),
            info.cpu_count_physical
        ),
        ("Linux", "unknown", 2)
    );
    f.write("/proc/sys/kernel/arch", "aarch64");
    assert_eq!(f.platform.info().unwrap().architecture, "aarch64");
    for bad in ["", "1 2", "bad 2 3", "1 bad 3", "1 2 bad"] {
        f.write("/proc/loadavg", bad);
        assert!(matches!(
            f.platform.load_average(),
            Err(PlatformError::Parse(_))
        ));
    }
    f.write("/proc/stat", "cpu 1\nbtime 2\n");
    assert!(matches!(
        f.platform.cpu_times(),
        Err(PlatformError::Parse(_))
    ));
    f.write(
        "/proc/meminfo",
        "MemTotal: 1 kB\nMemFree: 3 kB\nSwapFree: 99 kB\n",
    );
    let memory = f.platform.memory_info().unwrap();
    assert_eq!((memory.used_bytes, memory.swap_used_bytes), (0, 0));
    fs::remove_file(f.platform.path("/proc/sys/kernel/osrelease")).unwrap();
    fs::remove_file(f.platform.path("/.dockerenv")).unwrap_or(());
    f.write("/proc/1/cgroup", "0::/kubepods/test\n");
    let caps = f.platform.capabilities().unwrap();
    assert!(!caps.ebpf_available && caps.container_detected && !caps.cloud_detected);
    assert_eq!(LinuxPlatform::parse_kernel_version("5.8.0"), (5, 8));
    assert_eq!(LinuxPlatform::parse_kernel_version("invalid"), (0, 0));
}

#[test]
fn disk_snapshots_filter_partitions_pseudo_and_duplicate_mounts() {
    let f = Fixture::new();
    f.directory("/data");
    f.write("/proc/mounts", "malformed\ntmpfs /tmp tmpfs rw 0 0\nnone /none ext4 rw 0 0\n/dev/a /data ext4 rw 0 0\n/dev/a /duplicate ext4 rw 0 0\n/dev/missing /missing ext4 rw 0 0\n/dev/null /bad\0path ext4 rw 0 0\n");
    let disks = f.platform.disk_spaces().unwrap();
    assert_eq!(disks.len(), 1);
    let disk = &disks[0];
    assert_eq!(
        (
            disk.mount_point.as_str(),
            disk.device.as_str(),
            disk.filesystem.as_str()
        ),
        ("/data", "/dev/a", "ext4")
    );
    assert!(disk.total_bytes > 0 && disk.free_bytes <= disk.total_bytes);
    assert_eq!(disk.used_bytes, disk.total_bytes - disk.free_bytes);
    assert!(disk.inodes_used <= disk.inodes_total);
    f.write("/proc/diskstats", "bad\n8 0 sda 10 0 20 0 30 0 40 0 0 50 60\n8 1 sda1 10 0 20 0 30 0 40 0 0 50 60\n259 0 nvme0n1 10 0 20 0 30 0 40 0 0 50 60\n259 1 nvme0n1p1 10 0 20 0 30 0 40 0 0 50 60\n253 0 dm-0 10 0 20 0 30 0 40 0 0 50 60\n7 0 loop0 0 0 0 0 0 0 0 0 0 0 0\n");
    let io = f.platform.disk_io().unwrap();
    assert_eq!(
        io.iter().map(|d| d.device.as_str()).collect::<Vec<_>>(),
        ["sda", "nvme0n1", "dm-0"]
    );
    assert_eq!(
        (
            io[0].read_bytes,
            io[0].write_bytes,
            io[0].read_ops,
            io[0].write_ops
        ),
        (10_240, 20_480, 10, 30)
    );
    assert_eq!((io[0].io_time_ms, io[0].weighted_io_time_ms), (50, 60));
}

#[test]
fn socket_addresses_include_all_ipv6_words_and_reject_malformed_input() {
    assert_eq!(
        LinuxPlatform::parse_hex_addr_port("0100007F:1F90"),
        Some(("127.0.0.1".into(), 8080))
    );
    assert_eq!(
        LinuxPlatform::parse_hex_addr_port("00000000000000000000000001000000:01BB"),
        Some(("::1".into(), 443))
    );
    assert_eq!(
        LinuxPlatform::parse_hex_addr_port("B80D0120000000000000000002000000:0050"),
        Some(("2001:db8::2".into(), 80))
    );
    for invalid in [
        "bad",
        "0100007F:fffff",
        "GG00007F:0050",
        "abc:0050",
        "000000000000000000000000ZZ000000:0050",
        "éééééééééééééééé:0050",
    ] {
        assert!(
            LinuxPlatform::parse_hex_addr_port(invalid).is_none(),
            "invalid address accepted: {invalid}"
        );
    }
}

#[test]
fn network_counters_tcp_states_and_socket_owner_use_independent_proc_rows() {
    let f = Fixture::new();
    f.write("/proc/net/dev", "header\nheader\n\ninvalid\nlo: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\nshort: 1 2\neth0: 100 2 3 4 0 0 0 0 500 6 7 8 0 0 0 0\n");
    let counters = f.platform.network_counters().unwrap();
    assert_eq!(counters.len(), 1);
    assert_eq!(
        (
            counters[0].interface.as_str(),
            counters[0].bytes_recv,
            counters[0].bytes_sent
        ),
        ("eth0", 100, 500)
    );
    assert_eq!(
        (
            counters[0].packets_recv,
            counters[0].packets_sent,
            counters[0].errors_recv,
            counters[0].errors_sent,
            counters[0].drops_recv,
            counters[0].drops_sent
        ),
        (2, 6, 3, 7, 4, 8)
    );
    f.write("/proc/net/tcp", "header\n0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 4242\n1: 0100007F:0001 00000000:0000 01 0 0 0 0 0 1\n2: 0100007F:0002 00000000:0000 06 0 0 0 0 0 2\n3: 0100007F:0003 00000000:0000 08 0 0 0 0 0 3\n4: bad 0 ZZ\nshort\n");
    f.write("/proc/net/tcp6", "header\n0: 00000000000000000000000001000000:01BB 0 0A 0 0 0 0 0 9999\n1: invalid 0 0A 0 0 0 0 0 9\n2: 00000000:0050 0 0A 0 0 0 0 0 invalid\n");
    f.directory("/proc/123/fd");
    f.write("/proc/123/comm", "fixture-listener\n");
    symlink("socket:[4242]", f.platform.path("/proc/123/fd/4")).unwrap();
    symlink("/tmp/socket:[9999]", f.platform.path("/proc/123/fd/5")).unwrap();
    assert!(
        f.platform.find_pid_for_inode(9999).is_none(),
        "regular filename cannot impersonate a socket inode"
    );
    let tcp = f.platform.tcp_connections().unwrap();
    assert_eq!(
        (tcp.established, tcp.time_wait, tcp.close_wait, tcp.total),
        (1, 1, 1, 7)
    );
    let ports = f.platform.listening_ports().unwrap();
    assert_eq!(ports.len(), 2);
    assert_eq!(
        (
            ports[0].port,
            ports[0].pid,
            ports[0].bind_address.as_str(),
            ports[0].process_name.as_str()
        ),
        (8080, 123, "127.0.0.1", "fixture-listener")
    );
    assert_eq!(
        (
            ports[1].protocol.as_str(),
            ports[1].port,
            ports[1].pid,
            ports[1].bind_address.as_str()
        ),
        ("tcp6", 443, 0, "::1")
    );
}

#[test]
fn process_snapshot_handles_names_spaces_exits_and_truncated_stat_without_panicking() {
    let f = Fixture::new();
    f.write("/proc/meminfo", "MemTotal: 1000 kB\n");
    f.write(
        "/etc/passwd",
        "tester:x:1000:1000::/tmp:/bin/sh\nbroken\ninvalid:x:NaN\n",
    );
    let mut fields = vec!["0"; 22];
    fields[0] = "S";
    fields[17] = "4";
    fields[21] = "2";
    f.write(
        "/proc/123/stat",
        &format!("123 (name with ) parentheses) {}\n", fields.join(" ")),
    );
    f.write(
        "/proc/123/status",
        "Name: fixture\nUid:\t1000\t1000\t1000\t1000\n",
    );
    f.write("/proc/123/cmdline", "fixture\0--flag\0");
    f.directory("/proc/123/fd");
    f.write("/proc/123/fd/0", "");
    for (pid, stat) in [
        (124, "124 (truncated)"),
        (125, "125 )bad("),
        (126, "126 no delimiters"),
        (127, "127 (missing end"),
    ] {
        f.write(&format!("/proc/{pid}/stat"), stat);
    }
    f.directory("/proc/128");
    let processes = f.platform.processes().unwrap();
    assert_eq!(processes.len(), 1);
    let p = &processes[0];
    assert_eq!(
        (p.pid, p.name.as_str(), p.user.as_str(), p.state, p.threads),
        (123, "name with ) parentheses", "tester", 'S', 4)
    );
    assert_eq!(
        (p.memory_bytes, p.open_fds, p.cmdline.as_str()),
        (8192, 1, "fixture --flag")
    );
    assert!((p.memory_percent - 0.8).abs() < 0.0001);
    fs::remove_file(f.platform.path("/proc/123/status")).unwrap();
    fs::remove_dir_all(f.platform.path("/proc/123/fd")).unwrap();
    let processes = f.platform.processes().unwrap();
    assert_eq!(
        (processes[0].user.as_str(), processes[0].open_fds),
        ("0", -1)
    );
}

#[test]
fn interface_inventory_filters_loopback_down_and_link_local_addresses() {
    let f = Fixture::new();
    f.directory("/sys/class/net/lo");
    f.write("/sys/class/net/down0/operstate", "down\n");
    f.write("/sys/class/net/eth0/operstate", "up\n");
    f.write("/sys/class/net/eth0/address", "00:11:22:33:44:55\n");
    f.write("/sys/class/net/eth0/mtu", "1500\n");
    f.command("ip", "case \"$*\" in '-4 addr show eth0') printf '  inet 192.0.2.2/24 scope global\\n';; '-6 addr show eth0') printf '  inet6 fe80::1/64 scope link\\n  inet6 2001:db8::2/64 scope global\\n';; *) exit 1;; esac");
    let interfaces = f.platform.network_interfaces().unwrap();
    assert_eq!(interfaces.len(), 1);
    assert_eq!(
        (
            interfaces[0].name.as_str(),
            interfaces[0].mac.as_str(),
            interfaces[0].mtu
        ),
        ("eth0", "00:11:22:33:44:55", 1500)
    );
    assert_eq!(interfaces[0].ipv4, ["192.0.2.2"]);
    assert_eq!(interfaces[0].ipv6, ["2001:db8::2"]);
}

#[test]
fn users_include_primary_and_supplementary_groups_without_duplicates() {
    let f = Fixture::new();
    f.write("/etc/passwd", "tester:x:1000:10::/tmp:/bin/sh\nroot:x:0:0::/root:/bin/bash\ninvalid:x:NaN:0::/:/bin/sh\nshort\n");
    f.write(
        "/etc/group",
        "root:x:0:\nteam:x:10:tester\nops:x:20:tester, other\ninvalid\n",
    );
    let users = f.platform.users().unwrap();
    assert_eq!(users.len(), 2);
    assert_eq!(
        (
            users[0].username.as_str(),
            users[0].uid,
            users[0].shell.as_str()
        ),
        ("tester", 1000, "/bin/sh")
    );
    assert_eq!(users[0].groups, ["team", "ops"]);
    assert_eq!(users[1].groups, ["root"]);
}

#[test]
fn cgroup_v2_limits_units_unlimited_and_missing_files_are_distinct() {
    let f = Fixture::new();
    assert!(f.platform.cgroup_cpu().unwrap().is_none());
    assert!(f.platform.cgroup_memory().unwrap().is_none());
    f.write("/sys/fs/cgroup/cpu.max", "250000 100000\n");
    f.write(
        "/sys/fs/cgroup/cpu.stat",
        "nr_periods 1\nusage_usec 12345\n",
    );
    f.write("/sys/fs/cgroup/memory.max", "1048576\n");
    f.write("/sys/fs/cgroup/memory.current", "4096\n");
    let cpu = f.platform.cgroup_cpu().unwrap().unwrap();
    assert!(cpu.has_limit);
    assert_eq!((cpu.limit_cores, cpu.usage_ns), (2.5, 12_345_000));
    let memory = f.platform.cgroup_memory().unwrap().unwrap();
    assert!(memory.has_limit);
    assert_eq!((memory.limit_bytes, memory.usage_bytes), (1_048_576, 4096));
    f.write("/sys/fs/cgroup/cpu.max", "max 100000");
    f.write("/sys/fs/cgroup/memory.max", "max");
    assert!(!f.platform.cgroup_cpu().unwrap().unwrap().has_limit);
    assert!(!f.platform.cgroup_memory().unwrap().unwrap().has_limit);
    f.write("/sys/fs/cgroup/cpu.max", "1 0");
    assert_eq!(f.platform.cgroup_cpu().unwrap().unwrap().limit_cores, 0.0);
    f.write("/sys/fs/cgroup/cpu.max", "bad");
    assert!(f.platform.cgroup_cpu().unwrap().is_none());
}

#[test]
fn hashes_and_file_errors_are_real_and_defaults_still_target_the_host() {
    let f = Fixture::new();
    f.write("/data/file", "abc");
    let path = f.platform.path("/data/file");
    let path = path.to_str().unwrap();
    assert_eq!(
        f.platform.file_hash(path).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(f.platform.read_file_string(path).unwrap(), "abc");
    let missing = f.root.join("missing");
    assert!(matches!(
        f.platform.file_hash(missing.to_str().unwrap()),
        Err(PlatformError::Io(_))
    ));
    let default = LinuxPlatform::default();
    assert_eq!(default.path("/proc/stat"), PathBuf::from("/proc/stat"));
    assert!(default.command_dir.is_none());
}

#[test]
fn package_manager_fallbacks_and_service_status_use_fixture_commands_only() {
    let f = Fixture::new();
    f.command("dpkg-query", "printf 'lib-one\\t1.2.3\\ninvalid\\n'");
    let packages = f.platform.packages().unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(
        (
            packages[0].name.as_str(),
            packages[0].version.as_str(),
            packages[0].manager.as_str()
        ),
        ("lib-one", "1.2.3", "dpkg")
    );
    f.command("dpkg-query", "exit 1");
    f.command("rpm", "printf 'rpm-one\\t2.0-1\\n'");
    assert_eq!(f.platform.packages().unwrap()[0].manager, "rpm");
    f.command("rpm", "exit 1");
    f.command("apk", "printf 'lib-one-1.2-r3 x86_64 {lib-one} (MIT)\\n'");
    let packages = f.platform.packages().unwrap();
    assert_eq!(
        (
            packages[0].name.as_str(),
            packages[0].version.as_str(),
            packages[0].manager.as_str()
        ),
        ("lib-one", "1.2-r3", "apk")
    );
    f.command("apk", "exit 1");
    assert!(f.platform.packages().unwrap().is_empty());
    assert!(f.platform.services().unwrap().is_empty());
    f.command("systemctl", "case \"$*\" in 'list-units --type=service --all --no-pager --no-legend --plain') printf 'fixture.service loaded active running Fixture\\nfailed.service loaded failed dead Fixture\\nshort\\n';; 'is-enabled fixture.service') printf 'enabled\\n';; 'is-enabled failed.service') printf 'disabled\\n';; *) exit 1;; esac");
    let services = f.platform.services().unwrap();
    assert_eq!(services.len(), 2);
    assert_eq!(
        (
            services[0].name.as_str(),
            services[0].status.as_str(),
            services[0].enabled
        ),
        ("fixture", "active/running", true)
    );
    assert!(!services[1].enabled);
}

#[test]
fn cloud_provider_fallbacks_validate_headers_and_accept_standard_json_whitespace() {
    let f = Fixture::new();
    // Missing executable is an isolated no-cloud host; no real metadata request occurs.
    assert!(f.platform.cloud_info().unwrap().is_none());
    f.command("curl", "case \"$*\" in *latest/api/token*) printf 'fixture-token';; *'X-aws-ec2-metadata-token: fixture-token'*latest/meta-data/instance-id) printf 'i-fixture';; *'X-aws-ec2-metadata-token: fixture-token'*latest/meta-data/placement/region) printf 'us-test-1';; *'X-aws-ec2-metadata-token: fixture-token'*latest/meta-data/instance-type) printf 'test.small';; *'X-aws-ec2-metadata-token: fixture-token'*latest/meta-data/network/interfaces/macs/) printf 'aa:bb/';; *'X-aws-ec2-metadata-token: fixture-token'*latest/meta-data/network/interfaces/macs/aa:bb/vpc-id) printf 'vpc-fixture';; *) exit 1;; esac");
    let aws = f.platform.cloud_info().unwrap().unwrap();
    assert_eq!(
        (
            aws.provider.as_str(),
            aws.instance_id.as_str(),
            aws.region.as_str(),
            aws.instance_type.as_str(),
            aws.vpc_id.as_str()
        ),
        ("aws", "i-fixture", "us-test-1", "test.small", "vpc-fixture")
    );
    f.command("curl", "case \"$*\" in *'Metadata-Flavor: Google'*computeMetadata/v1/instance/id) printf 'gcp-fixture';; *'Metadata-Flavor: Google'*computeMetadata/v1/instance/zone) printf 'projects/1/zones/us-central1-a';; *'Metadata-Flavor: Google'*computeMetadata/v1/instance/machine-type) printf 'projects/1/machineTypes/test-small';; *'Metadata-Flavor: Google'*computeMetadata/v1/instance/network-interfaces/0/network) printf 'projects/1/networks/fixture-net';; *) exit 1;; esac");
    let gcp = f.platform.cloud_info().unwrap().unwrap();
    assert_eq!(
        (
            gcp.provider.as_str(),
            gcp.instance_id.as_str(),
            gcp.region.as_str(),
            gcp.instance_type.as_str(),
            gcp.vpc_id.as_str()
        ),
        (
            "gcp",
            "gcp-fixture",
            "us-central1",
            "test-small",
            "fixture-net"
        )
    );
    f.command("curl", "case \"$*\" in *'Metadata: true'*metadata/instance/compute*) printf '%s' '{ \"vmId\": \"azure-fixture\", \"location\": \"test-region\", \"vmSize\": \"test-size\", \"virtualMachineScaleSetId\": \"scale-fixture\" }';; *) exit 1;; esac");
    let azure = f.platform.cloud_info().unwrap().unwrap();
    assert_eq!(
        (
            azure.provider.as_str(),
            azure.instance_id.as_str(),
            azure.region.as_str(),
            azure.instance_type.as_str(),
            azure.vpc_id.as_str()
        ),
        (
            "azure",
            "azure-fixture",
            "test-region",
            "test-size",
            "scale-fixture"
        )
    );
    f.command("curl", "printf 'not-json'");
    assert!(f.platform.try_azure_imds().is_none());
    f.command("curl", "printf '{}'");
    assert!(f.platform.try_azure_imds().is_none());
    f.command("curl", "exit 1");
    assert!(f.platform.cloud_info().unwrap().is_none());
}

#[test]
fn fallback_identity_uses_persistent_state_migrates_legacy_and_fails_on_unwritable_state() {
    let f = Fixture::new();
    f.host();
    fs::remove_file(f.platform.path("/etc/machine-id")).unwrap();
    f.write(LEGACY_HOST_ID_PATH, "legacy-host-id\n");
    assert_eq!(f.platform.info().unwrap().machine_id, "legacy-host-id");
    let state = f.platform.path(FALLBACK_HOST_ID_PATH);
    assert!(state.starts_with(f.platform.path("/var/lib/aegis")));
    assert_eq!(fs::read_to_string(&state).unwrap(), "legacy-host-id");
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_file(f.platform.path(LEGACY_HOST_ID_PATH)).unwrap();
    assert_eq!(f.platform.info().unwrap().machine_id, "legacy-host-id");
    fs::write(&state, "").unwrap();
    assert!(
        f.platform.info().is_err(),
        "empty identity must not silently rotate"
    );
    fs::remove_file(&state).unwrap();
    fs::remove_dir(f.platform.path("/var/lib/aegis")).unwrap();
    f.write("/var/lib/aegis", "not a writable state directory");
    assert!(matches!(f.platform.info(), Err(PlatformError::Io(_))));
}

#[test]
fn unreadable_or_corrupt_legacy_state_never_silently_rotates_the_host() {
    let f = Fixture::new();
    f.host();
    fs::remove_file(f.platform.path("/etc/machine-id")).unwrap();
    f.directory(LEGACY_HOST_ID_PATH);
    assert!(matches!(f.platform.info(), Err(PlatformError::Io(_))));
    assert!(!f.platform.path(FALLBACK_HOST_ID_PATH).exists());
    fs::remove_dir(f.platform.path(LEGACY_HOST_ID_PATH)).unwrap();
    f.write(LEGACY_HOST_ID_PATH, "");
    assert!(matches!(f.platform.info(), Err(PlatformError::Parse(_))));
    fs::write(f.platform.path(LEGACY_HOST_ID_PATH), [0xff, 0xfe]).unwrap();
    assert!(matches!(f.platform.info(), Err(PlatformError::Io(_))));
    assert!(!f.platform.path(FALLBACK_HOST_ID_PATH).exists());
}
