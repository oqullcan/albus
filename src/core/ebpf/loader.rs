//! direct linux ebpf elf parser, map creation, cgroup sock_ops attachment, and perf ring buffer poller.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use tracing::{info, warn};

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_PROG_ATTACH: u32 = 8;
pub const BPF_PROG_DETACH: u32 = 9;

pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;

pub const BPF_PROG_TYPE_SOCK_OPS: u32 = 13;
pub const BPF_CGROUP_SOCK_OPS: u32 = 3;

pub const BPF_ANY: u64 = 0;
pub const BPF_PSEUDO_MAP_FD: u8 = 1;

// memory layout of connection event emitted across perf ring buffer
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RawConnEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub family: u8,
    pub reserved: [u8; 3],
    pub src_ip6: [u32; 4],
    pub dst_ip6: [u32; 4],
}

impl Default for RawConnEvent {
    fn default() -> Self {
        Self {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            seq: 0,
            ack: 0,
            family: 2, // AF_INET default
            reserved: [0; 3],
            src_ip6: [0; 4],
            dst_ip6: [0; 4],
        }
    }
}

// runtime configuration struct mirrored to ebpf array map
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BpfConfig {
    pub mss: u16,
    pub restore_mss: u16,
    pub restore_after_bytes: u32,
    pub min_mss: u16,
    pub enabled: u8,
    pub reserved: [u8; 5],
}

impl BpfConfig {
    pub fn new(
        mss: u16,
        restore_mss: u16,
        restore_after_bytes: u32,
        min_mss: u16,
        enabled: bool,
    ) -> Self {
        Self {
            mss,
            restore_mss,
            restore_after_bytes,
            min_mss,
            enabled: if enabled { 1 } else { 0 },
            reserved: [0; 5],
        }
    }
}

// manager wrapping ebpf maps, sock_ops program fd, and multi-core perf event readers
pub struct BpfEngine {
    pub prog_fd: RawFd,
    pub cgroup_fd: RawFd,
    pub config_map_fd: RawFd,
    pub target_ports_fd: RawFd,
    pub exclude_ips_fd: RawFd,
    pub exclude_ips_v6_fd: RawFd,
    pub conn_events_fd: RawFd,
    pub connections_fd: RawFd,
    pub perf_readers: Vec<PerfReader>,
    pub attached: bool,
    /// EBPF-03: false when some CPUs have no perf reader, so the callers that
    /// announce the engine as active can say "degraded" instead of implying
    /// decoy injection covers every connection. Never false with zero readers —
    /// that case is an Err now.
    pub readers_complete: bool,
}

impl BpfEngine {
    /// True when every CPU has a perf reader, i.e. decoy injection can observe
    /// every connection the program touches.
    pub fn readers_complete(&self) -> bool {
        self.readers_complete
    }

    /// Perf readers actually installed.
    pub fn reader_count(&self) -> usize {
        self.perf_readers.len()
    }
}

/// Opens a cgroup hierarchy directory for attachment.
///
/// PRIV-03: the open itself is the check. `O_NOFOLLOW` refuses a symlink at the
/// leaf, `O_DIRECTORY` refuses anything that is not a directory, and the
/// `fstat` on the resulting fd confirms the object that will be handed to
/// `bpf_prog_attach` is the directory we just opened — there is no
/// metadata-then-open window to lose.
///
/// Returns the `File` so the caller owns the descriptor; `load_and_attach`
/// deliberately leaks it (`mem::forget`) because the raw fd's lifetime is tied
/// to the program's attachment.
fn open_cgroup_dir(path: &str) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "security violation: cgroup path {} is not a directory",
                path
            ),
        ));
    }
    Ok(file)
}

fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

impl BpfEngine {
    // loads embedded elf bytecode, creates bpf maps, relocates symbols, and attaches to cgroup v2
    pub fn load_and_attach(cgroup_path: &str) -> Result<Self> {
        let elf_bytes = include_bytes!(env!("ALBUS_BPF_BYTECODE"));
        let num_cpus = get_possible_cpus().max(1);

        // 1. initialize ebpf kernel maps
        let config_map_fd = bpf_create_map(
            BPF_MAP_TYPE_ARRAY,
            4,
            std::mem::size_of::<BpfConfig>() as u32,
            1,
            "config_map",
        )?;
        let target_ports_fd = bpf_create_map(BPF_MAP_TYPE_HASH, 2, 1, 64, "target_ports")?;
        let exclude_ips_fd = bpf_create_map(BPF_MAP_TYPE_HASH, 4, 1, 64, "exclude_ips")?;
        let exclude_ips_v6_fd = bpf_create_map(BPF_MAP_TYPE_HASH, 16, 1, 64, "exclude_ips_v6")?;
        let conn_events_fd = bpf_create_map(
            BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            4,
            4,
            (num_cpus.max(128)) as u32,
            "conn_events",
        )?;
        let connections_fd = bpf_create_map(BPF_MAP_TYPE_LRU_HASH, 8, 8, 65536, "connections")?;

        let mut map_fds = HashMap::new();
        map_fds.insert("config_map".to_string(), config_map_fd);
        map_fds.insert("target_ports".to_string(), target_ports_fd);
        map_fds.insert("exclude_ips".to_string(), exclude_ips_fd);
        map_fds.insert("exclude_ips_v6".to_string(), exclude_ips_v6_fd);
        map_fds.insert("conn_events".to_string(), conn_events_fd);
        map_fds.insert("connections".to_string(), connections_fd);

        // 2. parse elf section headers and relocate pseudo map file descriptors
        let insns = parse_elf_sockops(elf_bytes, &map_fds).inspect_err(|_| {
            for fd in [
                config_map_fd,
                target_ports_fd,
                exclude_ips_fd,
                exclude_ips_v6_fd,
                conn_events_fd,
                connections_fd,
            ] {
                close_fd(fd);
            }
        })?;

        // 3. submit instructions to in-kernel bpf verifier
        let prog_fd = bpf_load_program(BPF_PROG_TYPE_SOCK_OPS, &insns, "albus_sockops")
            .inspect_err(|_| {
                for fd in [
                    config_map_fd,
                    target_ports_fd,
                    exclude_ips_fd,
                    exclude_ips_v6_fd,
                    conn_events_fd,
                    connections_fd,
                ] {
                    close_fd(fd);
                }
            })?;

        // 4. open cgroup hierarchy directory handle and attach program
        // validate: absolute, no .., not a symlink
        if cgroup_path.is_empty() || !cgroup_path.starts_with('/') || cgroup_path.contains("..") {
            close_fd(config_map_fd);
            close_fd(target_ports_fd);
            close_fd(exclude_ips_fd);
            close_fd(exclude_ips_v6_fd);
            close_fd(conn_events_fd);
            close_fd(connections_fd);
            return Err(Error::other(format!(
                "invalid cgroup path: {}",
                cgroup_path
            )));
        }
        // PRIV-03: the metadata test and the open were both path-based, so the
        // fd that received the sock_ops program need not be the directory that
        // was validated — any component writable by a lower-trust principal
        // could be swapped in the window between them. The fd decides which
        // sockets albus fragments and which flows get decoys.
        //
        // The codebase already has the right pattern in
        // `Config::load_from_file_root_checked` ("Opens with O_NOFOLLOW first,
        // then fstat-checks (no lstat->open TOCTOU)"); it was simply not applied
        // here. Same discipline now: open with O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC
        // FIRST, then fstat the fd that will actually be attached.
        let cgroup_file = open_cgroup_dir(cgroup_path).inspect_err(|_| {
            close_fd(config_map_fd);
            close_fd(target_ports_fd);
            close_fd(exclude_ips_fd);
            close_fd(exclude_ips_v6_fd);
            close_fd(conn_events_fd);
            close_fd(connections_fd);
        })?;
        let cgroup_fd = cgroup_file.as_raw_fd();
        std::mem::forget(cgroup_file); // maintain file descriptor lifecycle

        if let Err(e) = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS) {
            // avoid FD leak on attach failure
            unsafe {
                libc::close(cgroup_fd);
                libc::close(prog_fd);
                libc::close(config_map_fd);
                libc::close(target_ports_fd);
                libc::close(exclude_ips_fd);
                libc::close(exclude_ips_v6_fd);
                libc::close(conn_events_fd);
                libc::close(connections_fd);
            }
            return Err(Error::other(format!("bpf(BPF_PROG_ATTACH) failed: {}", e)));
        }

        // 5. allocate memory-mapped perf event ring buffers for each available cpu core
        //
        // EBPF-03: the per-CPU `PerfReader::new` failure used to be a `debug!`
        // and the loop simply continued, so the function returned
        // `Ok(BpfEngine { attached: true, perf_readers })` with an EMPTY (or
        // partial) reader set. That is a split-brain runtime state reported as
        // healthy: the kernel program is attached and shrinks TCP_MAXSEG on
        // every connection, and the MSS-restore state machine runs, but
        // `bpf_perf_event_output` writes into `conn_events` slots that have no
        // reader installed, so the userspace half never runs, no decoy
        // ClientHello is ever injected, and no log line reveals the absence.
        // Middlebox desynchronisation — the entire purpose of the second half of
        // the tool — was inert while the journal said the engine was active.
        //
        // The `debug!` was also below the default INFO max_level, so even the
        // failure was invisible at the default log level.
        let mut perf_readers = Vec::new();
        let mut readers_failed = 0usize;
        for cpu in 0..num_cpus {
            match PerfReader::new(cpu as i32) {
                Ok(reader) => {
                    let key = cpu as u32;
                    let val = reader.fd as u32;
                    // P4: a failed map update leaves that CPU's slot with no reader
                    // installed, which is exactly what a missing reader means to
                    // bpf_perf_event_output — the decoy ClientHello for that CPU is
                    // never injected. It was warn-only while the CPU still counted
                    // as complete, so readers_complete() stayed true and the engine
                    // logged "DPI bypass engine active" for a CPU it cannot cover.
                    // Same accounting as an attach failure.
                    if let Err(e) = bpf_map_update(conn_events_fd, &key, &val) {
                        readers_failed += 1;
                        warn!(
                            "bpf_map_update conn_events on cpu {}: {} (decoy injection \
                             will not run for this CPU)",
                            cpu, e
                        );
                    }
                    perf_readers.push(reader);
                }
                Err(e) => {
                    // raised from debug! to warn!: this is the difference
                    // between a working feature and a silently inert one.
                    readers_failed += 1;
                    warn!("could not attach perf event on cpu {}: {}", cpu, e);
                }
            }
        }

        // The reader set is the return channel for kernel data. If none could be
        // opened the engine cannot do the half of its job it claims, so this is
        // a failure — not a degraded success. Reuse the attach-failure close
        // sequence rather than adding a new one.
        if perf_readers.is_empty() {
            unsafe {
                libc::close(cgroup_fd);
                libc::close(prog_fd);
                libc::close(config_map_fd);
                libc::close(target_ports_fd);
                libc::close(exclude_ips_fd);
                libc::close(exclude_ips_v6_fd);
                libc::close(conn_events_fd);
                libc::close(connections_fd);
            }
            return Err(Error::other(format!(
                "eBPF program attached but NO perf event reader could be opened \
                 (0 of {} cpus, {} failures): refusing to report an engine that \
                 cannot receive kernel events",
                num_cpus, readers_failed
            )));
        }
        if readers_failed > 0 {
            // Partial is a real degradation too: decoy injection will silently
            // miss every connection established on a CPU whose reader is
            // missing. Say so explicitly instead of letting it pass unnoticed.
            warn!(
                "perf event readers available on only {}/{} cpus ({} failed): decoy \
                 injection will miss connections handled by the remaining cpus",
                perf_readers.len(),
                num_cpus,
                readers_failed
            );
        }

        info!(
            cgroup = %cgroup_path,
            readers = perf_readers.len(),
            cpus = num_cpus,
            "eBPF sock_ops attached successfully"
        );

        Ok(Self {
            prog_fd,
            cgroup_fd,
            config_map_fd,
            target_ports_fd,
            exclude_ips_fd,
            exclude_ips_v6_fd,
            conn_events_fd,
            connections_fd,
            perf_readers,
            attached: true,
            readers_complete: readers_failed == 0,
        })
    }
}

// lightweight copyable handles to ebpf map file descriptors for live runtime reconfiguration
#[derive(Debug, Clone, Copy)]
pub struct BpfMapHandles {
    pub config_map_fd: RawFd,
    pub target_ports_fd: RawFd,
    pub exclude_ips_fd: RawFd,
    pub exclude_ips_v6_fd: RawFd,
}

impl BpfMapHandles {
    // writes runtime parameters into index 0 of config_map
    pub fn push_config(&self, cfg: BpfConfig) -> Result<()> {
        let key = 0u32;
        bpf_map_update(self.config_map_fd, &key, &cfg)
    }

    // inserts target destination ports into lookup hash map
    pub fn push_target_ports(&self, ports: &[u16]) -> Result<()> {
        let val = 1u8;
        for &port in ports {
            bpf_map_update(self.target_ports_fd, &port, &val)?;
        }
        Ok(())
    }

    // inserts destination ipv4 addresses into exclusion map to bypass packet fragmentation
    pub fn push_exclude_ips(&self, ips: &[Ipv4Addr]) -> Result<()> {
        let val = 1u8;
        for ip in ips {
            let key = u32::from_ne_bytes(ip.octets());
            bpf_map_update(self.exclude_ips_fd, &key, &val)?;
        }
        Ok(())
    }

    // inserts destination ipv6 addresses into exclusion map to bypass packet fragmentation
    pub fn push_exclude_ips_v6(&self, ips: &[Ipv6Addr]) -> Result<()> {
        let val = 1u8;
        for ip in ips {
            let key = ip.octets();
            bpf_map_update(self.exclude_ips_v6_fd, &key, &val)?;
        }
        Ok(())
    }

    // synchronizes a set map to exactly `new`: deletes removed keys (stale
    // entries would otherwise stay active forever — insert-only reload left
    // shrunk configs partially applied), then inserts current keys.
    pub fn sync_target_ports(&self, old: &[u16], new: &[u16]) -> Result<()> {
        for port in old {
            if !new.contains(port) {
                bpf_map_delete(self.target_ports_fd, port)?;
            }
        }
        self.push_target_ports(new)
    }

    pub fn sync_exclude_ips(&self, old: &[Ipv4Addr], new: &[Ipv4Addr]) -> Result<()> {
        for ip in old {
            if !new.contains(ip) {
                let key = u32::from_ne_bytes(ip.octets());
                bpf_map_delete(self.exclude_ips_fd, &key)?;
            }
        }
        self.push_exclude_ips(new)
    }

    pub fn sync_exclude_ips_v6(&self, old: &[Ipv6Addr], new: &[Ipv6Addr]) -> Result<()> {
        for ip in old {
            if !new.contains(ip) {
                let key = ip.octets();
                bpf_map_delete(self.exclude_ips_v6_fd, &key)?;
            }
        }
        self.push_exclude_ips_v6(new)
    }
}

impl BpfEngine {
    // extracts lightweight copyable map descriptors for dynamic reconfiguration
    pub fn map_handles(&self) -> BpfMapHandles {
        BpfMapHandles {
            config_map_fd: self.config_map_fd,
            target_ports_fd: self.target_ports_fd,
            exclude_ips_fd: self.exclude_ips_fd,
            exclude_ips_v6_fd: self.exclude_ips_v6_fd,
        }
    }

    // writes runtime parameters into index 0 of config_map
    pub fn push_config(&self, cfg: BpfConfig) -> Result<()> {
        self.map_handles().push_config(cfg)
    }

    // inserts target destination ports into lookup hash map
    pub fn push_target_ports(&self, ports: &[u16]) -> Result<()> {
        self.map_handles().push_target_ports(ports)
    }

    // inserts destination ips into exclusion map to bypass packet fragmentation
    pub fn push_exclude_ips(&self, ips: &[Ipv4Addr]) -> Result<()> {
        self.map_handles().push_exclude_ips(ips)
    }

    // inserts destination ipv6 addresses into exclusion map to bypass packet fragmentation
    pub fn push_exclude_ips_v6(&self, ips: &[Ipv6Addr]) -> Result<()> {
        self.map_handles().push_exclude_ips_v6(ips)
    }

    // polls ring buffer pages across all active per-core perf readers
    pub fn poll_events<F>(&mut self, mut callback: F)
    where
        F: FnMut(RawConnEvent),
    {
        for reader in &mut self.perf_readers {
            reader.read_events(&mut callback);
        }
    }

    // detaches sock_ops program from cgroup v2 tree
    pub fn detach(&mut self) -> Result<()> {
        if self.attached {
            let res = bpf_prog_detach(self.cgroup_fd, BPF_CGROUP_SOCK_OPS);
            self.attached = false;
            res
        } else {
            Ok(())
        }
    }
}

impl Drop for BpfEngine {
    fn drop(&mut self) {
        let _ = self.detach();
        unsafe {
            if self.prog_fd >= 0 {
                libc::close(self.prog_fd);
            }
            if self.cgroup_fd >= 0 {
                libc::close(self.cgroup_fd);
            }
            if self.config_map_fd >= 0 {
                libc::close(self.config_map_fd);
            }
            if self.target_ports_fd >= 0 {
                libc::close(self.target_ports_fd);
            }
            if self.exclude_ips_fd >= 0 {
                libc::close(self.exclude_ips_fd);
            }
            if self.exclude_ips_v6_fd >= 0 {
                libc::close(self.exclude_ips_v6_fd);
            }
            if self.conn_events_fd >= 0 {
                libc::close(self.conn_events_fd);
            }
            if self.connections_fd >= 0 {
                libc::close(self.connections_fd);
            }
        }
    }
}

// executes bpf syscall with command opcode and attribute pointer
fn sys_bpf(cmd: u32, attr: *const libc::c_void, size: usize) -> libc::c_long {
    #[cfg(target_arch = "x86_64")]
    const SYS_BPF: libc::c_long = 321;
    #[cfg(target_arch = "aarch64")]
    const SYS_BPF: libc::c_long = 280;

    unsafe { libc::syscall(SYS_BPF, cmd, attr, size) }
}

fn bpf_create_map(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    name: &str,
) -> Result<RawFd> {
    #[repr(C)]
    struct BpfAttrMap {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        inner_map_fd: u32,
        numa_node: u32,
        map_name: [u8; 16],
        map_ifindex: u32,
        btf_fd: u32,
        btf_key_type_id: u32,
        btf_value_type_id: u32,
        btf_vmlinux_value_type_id: u32,
        map_extra: u64,
    }

    let mut attr: BpfAttrMap = unsafe { std::mem::zeroed() };
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;

    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    attr.map_name[..len].copy_from_slice(&bytes[..len]);

    let res = sys_bpf(
        BPF_MAP_CREATE,
        &attr as *const _ as *const libc::c_void,
        std::mem::size_of::<BpfAttrMap>(),
    );
    if res < 0 {
        Err(Error::other(format!(
            "bpf(BPF_MAP_CREATE, {}) failed: {}",
            name,
            Error::last_os_error()
        )))
    } else {
        Ok(res as RawFd)
    }
}

fn bpf_map_update<K, V>(map_fd: RawFd, key: &K, value: &V) -> Result<()> {
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let attr = BpfAttrMapElem {
        map_fd: map_fd as u32,
        pad: 0,
        key: key as *const _ as u64,
        value: value as *const _ as u64,
        flags: BPF_ANY,
    };

    let res = sys_bpf(
        BPF_MAP_UPDATE_ELEM,
        &attr as *const _ as *const libc::c_void,
        std::mem::size_of::<BpfAttrMapElem>(),
    );
    if res < 0 {
        Err(Error::other(format!(
            "bpf(BPF_MAP_UPDATE_ELEM) failed: {}",
            Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

fn bpf_map_delete<K>(map_fd: RawFd, key: &K) -> Result<()> {
    #[repr(C)]
    struct BpfAttrMapKey {
        map_fd: u32,
        pad: u32,
        key: u64,
    }

    let attr = BpfAttrMapKey {
        map_fd: map_fd as u32,
        pad: 0,
        key: key as *const _ as u64,
    };

    let res = sys_bpf(
        BPF_MAP_DELETE_ELEM,
        &attr as *const _ as *const libc::c_void,
        std::mem::size_of::<BpfAttrMapKey>(),
    );
    if res < 0 {
        let err = Error::last_os_error();
        // deleting an absent key already yields the desired state
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(Error::other(format!(
            "bpf(BPF_MAP_DELETE_ELEM) failed: {}",
            err
        )));
    }
    Ok(())
}

fn bpf_load_program(prog_type: u32, insns: &[BpfInsn], name: &str) -> Result<RawFd> {
    #[repr(C)]
    struct BpfAttrProg {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
    }

    let mut log_buf = vec![0u8; 65536];
    let license = b"GPL\0";

    let mut attr: BpfAttrProg = unsafe { std::mem::zeroed() };
    attr.prog_type = prog_type;
    attr.insn_cnt = insns.len() as u32;
    attr.insns = insns.as_ptr() as u64;
    attr.license = license.as_ptr() as u64;
    attr.log_level = 1;
    attr.log_size = log_buf.len() as u32;
    attr.log_buf = log_buf.as_mut_ptr() as u64;

    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    attr.prog_name[..len].copy_from_slice(&bytes[..len]);

    let res = sys_bpf(
        BPF_PROG_LOAD,
        &attr as *const _ as *const libc::c_void,
        std::mem::size_of::<BpfAttrProg>(),
    );
    if res < 0 {
        let log = String::from_utf8_lossy(&log_buf);
        let cleaned = log.trim_matches(char::from(0));
        // truncate verifier log to avoid kernel fingerprint leak into journal
        let short: String = cleaned.chars().take(4096).collect();
        Err(Error::other(format!(
            "bpf(BPF_PROG_LOAD) failed: {}\nBPF Verifier log (truncated):\n{}",
            Error::last_os_error(),
            short
        )))
    } else {
        Ok(res as RawFd)
    }
}

fn bpf_prog_attach(prog_fd: RawFd, target_fd: RawFd, attach_type: u32) -> Result<()> {
    #[repr(C)]
    struct BpfAttrAttach {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
        attach_flags: u32,
        replace_bpf_fd: u32,
    }

    let attr = BpfAttrAttach {
        target_fd: target_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };

    let res = sys_bpf(
        BPF_PROG_ATTACH,
        &attr as *const _ as *const libc::c_void,
        std::mem::size_of::<BpfAttrAttach>(),
    );
    if res < 0 {
        Err(Error::other(format!(
            "bpf(BPF_PROG_ATTACH) failed: {}",
            Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

fn bpf_prog_detach(target_fd: RawFd, attach_type: u32) -> Result<()> {
    #[repr(C)]
    struct BpfAttrDetach {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
    }

    let attr = BpfAttrDetach {
        target_fd: target_fd as u32,
        attach_bpf_fd: 0,
        attach_type,
    };

    let res = sys_bpf(
        BPF_PROG_DETACH,
        &attr as *const _ as *const libc::c_void,
        std::mem::size_of::<BpfAttrDetach>(),
    );
    if res < 0 {
        Err(Error::other(format!(
            "bpf(BPF_PROG_DETACH) failed: {}",
            Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_reg: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_reg: (src << 4) | (dst & 0x0F),
            off,
            imm,
        }
    }
}

// parses 64-bit elf structure, locates sock_ops bytecode and relocates map indices
pub fn parse_elf_sockops(
    elf_bytes: &[u8],
    map_fds: &HashMap<String, RawFd>,
) -> Result<Vec<BpfInsn>> {
    if elf_bytes.len() < 64 || &elf_bytes[0..4] != b"\x7FELF" {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid ELF binary format",
        ));
    }

    let e_shoff = u64::from_le_bytes(
        elf_bytes
            .get(40..48)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "truncated ehdr"))?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "ehdr conv"))?,
    ) as usize;
    let e_shentsize = u16::from_le_bytes(
        elf_bytes
            .get(58..60)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "truncated ehdr"))?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "ehdr conv"))?,
    ) as usize;
    let e_shnum = u16::from_le_bytes(
        elf_bytes
            .get(60..62)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "truncated ehdr"))?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "ehdr conv"))?,
    ) as usize;
    let e_shstrndx = u16::from_le_bytes(
        elf_bytes
            .get(62..64)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "truncated ehdr"))?
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "ehdr conv"))?,
    ) as usize;

    if e_shentsize < 64 || e_shnum == 0 || e_shnum > 64 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid section header count/size",
        ));
    }
    // EBPF-05: e_shstrndx indexes the section header table and was never checked
    // against e_shnum, so an out-of-range value sliced past the validated table.
    if e_shstrndx >= e_shnum {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "e_shstrndx out of range",
        ));
    }

    // EBPF-05: one bounds-checked accessor for every file-controlled offset. The
    // function already used checked_mul/checked_add and explicit range checks at
    // five sibling sites; these five were the paths not brought under it. Every
    // failure below was a Rust slice-index panic, never an out-of-bounds access,
    // so this is robustness, not a memory-safety fix — but a panic at startup is
    // still a startup abort if a malformed object were ever embedded.
    let region = |off: usize, size: usize| -> Result<&[u8]> {
        let end = off
            .checked_add(size)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "section extent overflow"))?;
        elf_bytes
            .get(off..end)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "section out of bounds"))
    };
    let table_len = e_shnum
        .checked_mul(e_shentsize)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "sh overflow"))?;
    let table_end = e_shoff
        .checked_add(table_len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "sh overflow"))?;
    if table_end > elf_bytes.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "ELF section header table out of bounds",
        ));
    }

    let shstrtab_hdr_offset = (e_shoff + (e_shstrndx * e_shentsize))
        .checked_sub(0)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "shstrtab hdr overflow"))?;
    let hdr = region(shstrtab_hdr_offset, 40)?;
    let shstrtab_offset = u64::from_le_bytes(hdr[24..32].try_into().unwrap()) as usize;
    let shstrtab_size = u64::from_le_bytes(hdr[32..40].try_into().unwrap()) as usize;
    let shstrtab = region(shstrtab_offset, shstrtab_size)?;

    let get_sh_name = |name_offset: usize| -> String {
        if name_offset < shstrtab.len() {
            let slice = &shstrtab[name_offset..];
            let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            String::from_utf8_lossy(&slice[..end]).to_string()
        } else {
            String::new()
        }
    };

    let mut sockops_section = None;
    let mut symtab_section = None;
    let mut strtab_section = None;
    let mut rel_section = None;

    for i in 0..e_shnum {
        let sh_offset = e_shoff + (i * e_shentsize);
        let sh_name_off =
            u32::from_le_bytes(elf_bytes[sh_offset..sh_offset + 4].try_into().unwrap()) as usize;
        let sh_type =
            u32::from_le_bytes(elf_bytes[sh_offset + 4..sh_offset + 8].try_into().unwrap());
        let sh_offset_val = u64::from_le_bytes(
            elf_bytes[sh_offset + 24..sh_offset + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let sh_size = u64::from_le_bytes(
            elf_bytes[sh_offset + 32..sh_offset + 40]
                .try_into()
                .unwrap(),
        ) as usize;
        let sh_link = u32::from_le_bytes(
            elf_bytes[sh_offset + 40..sh_offset + 44]
                .try_into()
                .unwrap(),
        ) as usize;
        let sh_entsize_val = u64::from_le_bytes(
            elf_bytes[sh_offset + 56..sh_offset + 64]
                .try_into()
                .unwrap(),
        ) as usize;

        let name = get_sh_name(sh_name_off);

        if name == "sockops" || (sh_type == 1 && name.contains("sockops")) {
            sockops_section = Some((i, sh_offset_val, sh_size));
        } else if sh_type == 2 || name == ".symtab" {
            symtab_section = Some((sh_offset_val, sh_size, sh_link));
        } else if sh_type == 3 && (name == ".strtab" || (strtab_section.is_none() && i == 1)) {
            strtab_section = Some((sh_offset_val, sh_size));
        } else if (sh_type == 4 || sh_type == 9)
            && (name == ".relsockops"
                || name == ".rel.sockops"
                || name == ".relasockops"
                || name == ".rela.sockops")
        {
            let ent_size = if sh_entsize_val > 0 {
                sh_entsize_val
            } else if sh_type == 4 {
                24
            } else {
                16
            };
            rel_section = Some((sh_type, sh_offset_val, sh_size, ent_size));
        }
    }

    let (_, code_offset, code_size) = sockops_section.ok_or_else(|| {
        Error::new(
            ErrorKind::NotFound,
            "could not find 'sockops' program section in BPF ELF",
        )
    })?;

    let code_end = code_offset
        .checked_add(code_size)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "code overflow"))?;
    if code_end > elf_bytes.len() || code_size % 8 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "sockops section out of bounds",
        ));
    }
    let code_bytes = &elf_bytes[code_offset..code_end];
    let mut insns = Vec::with_capacity(code_size / 8);

    for chunk in code_bytes.as_chunks::<8>().0 {
        insns.push(BpfInsn {
            code: chunk[0],
            dst_reg: chunk[1],
            off: i16::from_le_bytes([chunk[2], chunk[3]]),
            imm: i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        });
    }

    // perform map file descriptor relocation for ld_imm64 instructions
    if let (Some((sym_off, sym_size, sym_link)), Some((_, rel_off, rel_size, entry_size))) =
        (symtab_section, rel_section)
    {
        let strtab = if sym_link < e_shnum {
            let str_hdr = e_shoff + (sym_link * e_shentsize);
            let s_off =
                u64::from_le_bytes(elf_bytes[str_hdr + 24..str_hdr + 32].try_into().unwrap())
                    as usize;
            let s_size =
                u64::from_le_bytes(elf_bytes[str_hdr + 32..str_hdr + 40].try_into().unwrap())
                    as usize;
            if s_off + s_size <= elf_bytes.len() {
                &elf_bytes[s_off..s_off + s_size]
            } else {
                &[]
            }
        } else if let Some((str_off, str_size)) = strtab_section {
            // EBPF-05: this branch had no range check, unlike the sym_link branch
            // above it — the same fallback was safe on one path and panicking on
            // the other.
            match elf_bytes.get(
                str_off
                    ..str_off.checked_add(str_size).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "strtab extent overflow")
                    })?,
            ) {
                Some(slice) => slice,
                None => &[],
            }
        } else {
            &[]
        };

        let get_sym_name = |name_offset: usize| -> String {
            if name_offset < strtab.len() {
                let slice = &strtab[name_offset..];
                let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                String::from_utf8_lossy(&slice[..end]).to_string()
            } else {
                String::new()
            }
        };

        // EBPF-05: num_syms came from an unvalidated sh_size and the loop then
        // read 4 bytes per entry with no bound against the buffer. Validate the
        // whole symtab extent once.
        region(sym_off, sym_size)?;
        let num_syms = sym_size / 24;
        let mut symbols = Vec::with_capacity(num_syms.min(65536));
        for i in 0..num_syms {
            let Some(s_off) = sym_off.checked_add(i * 24) else {
                break;
            };
            let Some(st) = elf_bytes.get(s_off..s_off + 4) else {
                break;
            };
            let st_name = u32::from_le_bytes(st.try_into().unwrap()) as usize;
            symbols.push(get_sym_name(st_name));
        }

        // EBPF-05: same for the relocation scan, plus the fixed 16-byte read at
        // r_off+8 ignored the declared sh_entsize, so a bogus small non-zero
        // entry_size both misparsed and ran off the section.
        if entry_size < 16 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "relocation entry size below 16",
            ));
        }
        region(rel_off, rel_size)?;
        let num_rels = rel_size / entry_size;

        for i in 0..num_rels {
            let Some(r_off) = rel_off.checked_add(i * entry_size) else {
                break;
            };
            // EBPF-05: the 16-byte read was unchecked; the whole relocation
            // extent is already validated above, so bound each entry too.
            let Some(entry) = elf_bytes.get(r_off..r_off + 16) else {
                break;
            };
            let r_offset = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
            let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            let sym_idx = (r_info >> 32) as usize;

            let insn_idx = r_offset / 8;
            if insn_idx < insns.len() && sym_idx < symbols.len() {
                let sym_name = &symbols[sym_idx];
                if let Some(&fd) = map_fds.get(sym_name) {
                    insns[insn_idx].dst_reg =
                        (BPF_PSEUDO_MAP_FD << 4) | (insns[insn_idx].dst_reg & 0x0F);
                    insns[insn_idx].imm = fd;
                }
            }
        }
    }

    Ok(insns)
}

// reads possible cpu cores configured in sysfs
fn get_possible_cpus() -> usize {
    if let Ok(content) = fs::read_to_string("/sys/devices/system/cpu/possible") {
        if let Some(last) = content.trim().split('-').next_back() {
            if let Ok(num) = last.parse::<usize>() {
                return num + 1;
            }
        }
    }
    1
}

// wraps memory-mapped circular ring buffer allocated via perf_event_open
pub struct PerfReader {
    pub fd: RawFd,
    page_size: usize,
    mmap_ptr: *mut libc::c_void,
    mmap_size: usize,
}

unsafe impl Send for PerfReader {}
unsafe impl Sync for PerfReader {}

impl PerfReader {
    pub fn new(cpu: i32) -> Result<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let num_pages: usize = 8;
        debug_assert!(
            num_pages.is_power_of_two(),
            "perf ring pages must be power-of-two"
        );
        let mmap_size = (1 + num_pages) * page_size;

        #[repr(C)]
        struct PerfEventAttr {
            event_type: u32,
            size: u32,
            config: u64,
            sample_period: u64,
            sample_type: u64,
            read_format: u64,
            flags: u64,
            wakeup_events: u32,
            bp_type: u32,
            config1: u64,
            config2: u64,
            branch_sample_type: u64,
            sample_regs_user: u64,
            sample_stack_user: u32,
            clockid: i32,
            sample_regs_intr: u64,
            aux_watermark: u32,
            sample_max_stack: u16,
            reserved: u16,
        }

        const PERF_TYPE_SOFTWARE: u32 = 1;
        const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
        const PERF_SAMPLE_RAW: u64 = 1 << 10;

        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.event_type = PERF_TYPE_SOFTWARE;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = PERF_COUNT_SW_BPF_OUTPUT;
        attr.sample_period = 1;
        attr.sample_type = PERF_SAMPLE_RAW;
        attr.wakeup_events = 1;

        #[cfg(target_arch = "x86_64")]
        const SYS_PERF_EVENT_OPEN: libc::c_long = 298;
        #[cfg(target_arch = "aarch64")]
        const SYS_PERF_EVENT_OPEN: libc::c_long = 241;

        let fd = unsafe {
            libc::syscall(
                SYS_PERF_EVENT_OPEN,
                &attr as *const _ as *const libc::c_void,
                -1,
                cpu,
                -1,
                0,
            ) as RawFd
        };

        if fd < 0 {
            return Err(Error::last_os_error());
        }

        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if mmap_ptr == libc::MAP_FAILED {
            let err = Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 9216;
        unsafe {
            libc::ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        }

        Ok(Self {
            fd,
            page_size,
            mmap_ptr,
            mmap_size,
        })
    }

    // decodes sample records from volatile data_head to data_tail ring boundary
    pub fn read_events<F>(&mut self, callback: &mut F)
    where
        F: FnMut(RawConnEvent),
    {
        #[repr(C)]
        struct PerfEventMmapPage {
            _pad: [u8; 1024],
            data_head: u64,
            data_tail: u64,
            data_offset: u64,
            data_size: u64,
        }

        let header = unsafe { &mut *(self.mmap_ptr as *mut PerfEventMmapPage) };
        let head = unsafe { std::ptr::read_volatile(&header.data_head) };
        let mut tail = unsafe { std::ptr::read_volatile(&header.data_tail) };

        if head == tail {
            return;
        }

        // smp_rmb: synchronize with kernel's perf ring write before reading data section
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);

        let data_ptr = unsafe { (self.mmap_ptr as *const u8).add(self.page_size) };
        let data_len = self.mmap_size - self.page_size;
        let data_mask = data_len - 1;

        let read_ring_bytes = |offset: usize, dst: &mut [u8]| {
            for (i, b) in dst.iter_mut().enumerate() {
                let idx = (offset + i) & data_mask;
                *b = unsafe { *data_ptr.add(idx) };
            }
        };

        while tail < head {
            let record_offset = (tail as usize) & data_mask;

            let mut hdr_bytes = [0u8; 8];
            read_ring_bytes(record_offset, &mut hdr_bytes);

            let event_type = u32::from_ne_bytes(hdr_bytes[0..4].try_into().unwrap());
            let size = u16::from_ne_bytes(hdr_bytes[6..8].try_into().unwrap()) as usize;

            if size == 0 || tail + (size as u64) > head {
                break;
            }

            const PERF_RECORD_SAMPLE: u32 = 9;
            if event_type == PERF_RECORD_SAMPLE {
                let mut len_bytes = [0u8; 4];
                read_ring_bytes((record_offset + 8) & data_mask, &mut len_bytes);
                let raw_size = u32::from_ne_bytes(len_bytes) as usize;

                if raw_size >= std::mem::size_of::<RawConnEvent>() {
                    let mut evt_bytes = [0u8; std::mem::size_of::<RawConnEvent>()];
                    read_ring_bytes((record_offset + 12) & data_mask, &mut evt_bytes);
                    let event =
                        unsafe { std::ptr::read(evt_bytes.as_ptr() as *const RawConnEvent) };
                    callback(event);
                }
            }

            tail += size as u64;
        }

        // smp_mb: ensure all ring data reads have completed before advancing data_tail
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        unsafe {
            std::ptr::write_volatile(&mut header.data_tail, tail);
        }
    }
}

impl Drop for PerfReader {
    fn drop(&mut self) {
        unsafe {
            if !self.mmap_ptr.is_null() && self.mmap_ptr != libc::MAP_FAILED {
                libc::munmap(self.mmap_ptr, self.mmap_size);
            }
            if self.fd >= 0 {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_parser_relocation_integrity() {
        let elf_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/sockops.bpf.o"));
        assert!(elf_bytes.len() > 100);

        let mut map_fds = HashMap::new();
        map_fds.insert("config_map".to_string(), 100);
        map_fds.insert("exclude_ips".to_string(), 101);
        map_fds.insert("exclude_ips_v6".to_string(), 105);
        map_fds.insert("target_ports".to_string(), 102);
        map_fds.insert("conn_events".to_string(), 103);
        map_fds.insert("connections".to_string(), 104);

        let insns = parse_elf_sockops(elf_bytes, &map_fds).expect("elf parsing should succeed");
        assert!(!insns.is_empty(), "instructions must not be empty");

        let imms: Vec<i32> = insns.iter().map(|i| i.imm).collect();
        assert!(
            imms.contains(&100),
            "config_map relocation (fd 100) must be applied"
        );
        assert!(
            imms.contains(&101),
            "exclude_ips relocation (fd 101) must be applied"
        );
        assert!(
            imms.contains(&105),
            "exclude_ips_v6 relocation (fd 105) must be applied"
        );
        assert!(
            imms.contains(&102),
            "target_ports relocation (fd 102) must be applied"
        );
        assert!(
            imms.contains(&103),
            "conn_events relocation (fd 103) must be applied"
        );
        assert!(
            imms.contains(&104),
            "connections relocation (fd 104) must be applied"
        );

        let conn_count = imms.iter().filter(|&&imm| imm == 104).count();
        assert_eq!(
            conn_count, 3,
            "connections map should be relocated 3 times in bpf bytecode"
        );
    }

    #[test]
    fn test_perf_reader_creation() {
        if let Ok(mut reader) = PerfReader::new(0) {
            let mut count = 0;
            reader.read_events(&mut |_evt| {
                count += 1;
            });
            assert_eq!(count, 0);
        }
    }
}

#[cfg(test)]
mod perf_reader_policy_tests {

    /// EBPF-03's decision, extracted so it is testable without touching the
    /// kernel: no BPF map, cgroup, syscall or raw socket is involved.
    ///
    /// The policy is deliberately split:
    ///   * zero readers -> Err. The engine cannot receive a single kernel event,
    ///     so every decoy ClientHello would silently never be injected while the
    ///     daemon reported the engine active. That is a total failure wearing a
    ///     success record.
    ///   * partial -> Ok but explicitly degraded, surfaced to the caller so it
    ///     cannot be described as fully active.
    #[derive(Debug, PartialEq, Eq)]
    enum ReaderPolicy {
        Ok { degraded: bool },
        Err,
    }

    fn reader_policy(ok: usize, attempted: usize) -> ReaderPolicy {
        if ok == 0 {
            ReaderPolicy::Err
        } else if ok < attempted {
            ReaderPolicy::Ok { degraded: true }
        } else {
            ReaderPolicy::Ok { degraded: false }
        }
    }

    /// The headline case: every perf_event_open fails. Today this produced
    /// `Ok(BpfEngine { attached: true, perf_readers: [] })`.
    #[test]
    fn test_all_readers_failing_is_an_error() {
        assert_eq!(
            reader_policy(0, 8),
            ReaderPolicy::Err,
            "an engine that cannot receive kernel events must not report success"
        );
    }

    /// A strict subset — e.g. an offline CPU index in
    /// /sys/devices/system/cpu/possible — is a real degradation, and must be an
    /// explicit recorded state rather than silence.
    #[test]
    fn test_partial_readers_is_degraded_buccessful() {
        assert_eq!(
            reader_policy(5, 8),
            ReaderPolicy::Ok { degraded: true },
            "a partial reader set must be reported as degraded"
        );
        assert_eq!(reader_policy(1, 8), ReaderPolicy::Ok { degraded: true });
    }

    #[test]
    fn test_all_readers_available_is_fully_successful() {
        assert_eq!(reader_policy(8, 8), ReaderPolicy::Ok { degraded: false });
        assert_eq!(
            reader_policy(1, 1),
            ReaderPolicy::Ok { degraded: false },
            "a single-CPU host with its one reader present is not degraded"
        );
    }

    /// And the production loop must actually apply this policy — a test of the
    /// helper alone would prove nothing.
    #[test]
    fn test_production_loop_enforces_the_zero_reader_policy() {
        let src = include_str!("loader.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod perf_reader_policy_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("if perf_readers.is_empty() {")
            .expect("zero-reader guard");
        let block = &prod[at..(at + 900).min(prod.len())];
        assert!(
            block.contains("return Err("),
            "zero readers must return Err: {}",
            block
        );
        assert!(
            block.contains("libc::close("),
            "the attach-failure close sequence must be reused so no fd leaks: {}",
            block
        );
        assert!(
            block.contains("close(cgroup_fd)"),
            "the attached program must be torn down too: {}",
            block
        );
    }

    /// The per-CPU failure must be visible at the default log level. It was a
    /// `debug!`, below the default INFO max_level.
    #[test]
    fn test_per_cpu_reader_failure_is_logged_at_warn() {
        let src = include_str!("loader.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod perf_reader_policy_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("could not attach perf event on cpu")
            .expect("per-cpu failure log");
        let before = &prod[..at];
        let line_start = before.rfind('\n').map(|i| i + 1).unwrap_or(0);
        assert!(
            prod[line_start..at].trim_start().starts_with("warn!"),
            "a failed perf reader must be warn!, not debug! — it is the difference \
             between a working feature and a silently inert one"
        );
    }

    /// Partial coverage must be reported, not merely counted.
    #[test]
    fn test_partial_coverage_is_logged_explicitly() {
        let src = include_str!("loader.rs");
        let prod = src
            .split_once(
                "
#[cfg(test)]
mod perf_reader_policy_tests",
            )
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(
            prod.contains("will miss connections"),
            "a partial reader set must say what it costs"
        );
    }

    /// And the daemon must not call a degraded engine "active".
    #[test]
    fn test_degraded_engine_is_not_announced_as_active() {
        let src = include_str!("../engine.rs");
        let at = src
            .find("eBPF sock_ops DPI bypass engine active")
            .expect("active log");
        let before = &src[..at];
        assert!(
            before.contains("if complete {"),
            "the active announcement must be gated on complete reader coverage"
        );
        assert!(
            src.contains("DPI bypass engine DEGRADED"),
            "a degraded engine must say so"
        );
    }
}

#[cfg(test)]
mod cgroup_open_tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("albus-cgroup-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("tmpdir");
        d
    }

    /// PRIV-03's headline case: a symlink where a directory is expected. The old
    /// code ran `symlink_metadata` (which refuses a symlinked leaf) and then
    /// `File::open` on the PATH — and `File::open` follows symlinks. So the fd
    /// handed to `bpf_prog_attach` could be the symlink's target even though the
    /// metadata test had "passed" moments earlier on a different object.
    #[test]
    fn test_open_refuses_a_symlink_at_the_leaf() {
        let d = tmpdir("symlink");
        let real = d.join("real");
        fs::create_dir_all(&real).expect("real dir");
        let link = d.join("cgroup");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let r = open_cgroup_dir(link.to_str().expect("path"));
        assert!(
            r.is_err(),
            "PRIV-03: O_NOFOLLOW must refuse a symlinked leaf, so the attached fd \\
             can never be the link target"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// A regular file where a directory is expected must be refused.
    #[test]
    fn test_open_refuses_a_regular_file() {
        let d = tmpdir("regular");
        let f = d.join("cgroup");
        fs::write(&f, b"not a directory").expect("write");

        let r = open_cgroup_dir(f.to_str().expect("path"));
        assert!(r.is_err(), "O_DIRECTORY must refuse a non-directory");

        let _ = fs::remove_dir_all(&d);
    }

    /// The positive control: a real directory opens and is a directory.
    #[test]
    fn test_open_accepts_a_real_directory() {
        let d = tmpdir("real");
        let ok = open_cgroup_dir(d.to_str().expect("path")).expect("must open");
        assert!(ok.metadata().expect("metadata").file_type().is_dir());

        let _ = fs::remove_dir_all(&d);
    }

    /// A missing path is an error, not a silent default.
    #[test]
    fn test_open_reports_a_missing_path() {
        let d = tmpdir("missing");
        let r = open_cgroup_dir(d.join("nope").to_str().expect("path"));
        assert!(
            r.is_err(),
            "a missing cgroup path must be an explicit error"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// And `validate_cgroup_path` and the loader must agree on what they accept,
    /// so a path that config validation permits is not then refused (or
    /// vice-versa) at attach time.
    #[test]
    fn test_validator_and_loader_agree_on_shape() {
        let d = tmpdir("agree");
        let real = d.join("real");
        fs::create_dir_all(&real).expect("real dir");

        // shape checks that do not need the path to exist
        assert!(crate::app::config::validate_cgroup_path_for_test("relative/path").is_err());
        assert!(crate::app::config::validate_cgroup_path_for_test("/a/../b").is_err());

        // an existing real directory: both accept
        let real_s = real.to_str().expect("path");
        assert!(
            crate::app::config::validate_cgroup_path_for_test(real_s).is_ok(),
            "an existing real directory must pass validation"
        );
        assert!(
            open_cgroup_dir(real_s).is_ok(),
            "and the loader must be able to open the same path"
        );

        // a symlink to a real directory: the loader must refuse even though the
        // symlink resolves to a perfectly good directory
        let link = d.join("cgroup");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let link_s = link.to_str().expect("path");
        assert!(
            crate::app::config::validate_cgroup_path_for_test(link_s).is_err(),
            "validation already refuses a symlinked leaf"
        );
        assert!(
            open_cgroup_dir(link_s).is_err(),
            "and the loader must agree rather than following it"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// Regression guard: the path-based metadata test must be gone from the
    /// attach path.
    #[test]
    fn test_attach_path_does_not_use_a_metadata_then_open_sequence() {
        let src = include_str!("loader.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod cgroup_open_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("// 4. open cgroup hierarchy directory handle")
            .expect("the attach section");
        let tail = &prod[at..];
        let end = tail
            .find("bpf_prog_attach(")
            .map(|o| at + o)
            .unwrap_or(prod.len());
        let block = &prod[at..end];
        assert!(
            !block.contains("symlink_metadata(cgroup_path)"),
            "PRIV-03: a metadata test followed by a path open is the TOCTOU — the \\
             open must be the check"
        );
        assert!(
            block.contains("open_cgroup_dir("),
            "the attach path must open through the O_NOFOLLOW|O_DIRECTORY helper"
        );
        assert!(
            !block.contains("File::open(cgroup_path)"),
            "a plain path open must not remain on the attach path"
        );
    }
}

#[cfg(test)]
mod elf_range_tests {
    use super::*;

    /// EBPF-05 is explicitly NOT a security finding: the parser's only input is
    /// `include_bytes!` from build.rs, so no untrusted party reaches it, and
    /// every defect was a Rust slice-index panic rather than an out-of-bounds
    /// access. What it is, is robustness — and the audit's own prescription is
    /// to convert five panic paths into clean `Err` returns.
    ///
    /// These fixtures are byte literals: no BPF syscall, no cgroup, no perf
    /// event, no network.
    /// Builds a minimal ELF64 with `shnum` section headers and the given
    /// `e_shstrndx`, so the section table itself is valid.
    fn elf_with(shnum: u16, shstrndx: u16, shoff: u64) -> Vec<u8> {
        let shentsize: u16 = 64;
        let table_len = shnum as usize * shentsize as usize;
        let total = shoff as usize + table_len;
        let mut e = vec![0u8; total.max(0x40)];
        e[0] = 0x7f;
        e[1] = b'E';
        e[2] = b'L';
        e[3] = b'F';
        e[4] = 2; // ELFCLASS64
        e[5] = 1; // little endian
        e[6] = 1; // version
        e[16..18].copy_from_slice(&1u16.to_le_bytes()); // e_type ET_REL
        e[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine
        e[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        e[32..40].copy_from_slice(&shoff.to_le_bytes()); // e_shoff
        e[52..54].copy_from_slice(&shnum.to_le_bytes()); // e_shnum
        e[58..60].copy_from_slice(&shstrndx.to_le_bytes()); // e_shstrndx
        e[60..62].copy_from_slice(&shentsize.to_le_bytes()); // e_shentsize
        e
    }

    /// A malformed ELF must return Err, not panic. `catch_unwind` makes the
    /// distinction explicit: the audit's requirement is that it *returns*.
    fn assert_returns_err(bytes: &[u8], what: &str) {
        let fds: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            parse_elf_sockops(bytes, &fds).is_err()
        }));
        assert!(
            result.unwrap_or(false),
            "{}: parse_elf_sockops must RETURN Err, not panic",
            what
        );
    }

    /// (a) `e_shstrndx` was read from bytes 62..64 and never checked against
    /// `e_shnum`, so an out-of-range index sliced past the validated table.
    #[test]
    fn test_parse_elf_rejects_out_of_range_shstrndx() {
        let e = elf_with(4, 99, 0x40);
        assert_returns_err(&e, "e_shstrndx=99 with e_shnum=4");
    }

    /// (b) the shstrtab was sliced with two file-controlled values and no range
    /// check, and the addition could wrap in release builds.
    #[test]
    fn test_parse_elf_rejects_oversized_section_extents() {
        let shoff = 0x40u64;
        let mut e = elf_with(2, 1, shoff);
        // Section header 1 (the shstrtab) claims sh_offset = 0, sh_size huge.
        let hdr = (shoff + 64) as usize;
        e[hdr + 24..hdr + 32].copy_from_slice(&0u64.to_le_bytes());
        e[hdr + 32..hdr + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_returns_err(&e, "shstrtab extent of u64::MAX");
    }

    /// (d) the symbol scan derived num_syms from an unvalidated sh_size and read
    /// 4 bytes per entry with no bound.
    #[test]
    fn test_parse_elf_rejects_symtab_past_end_of_buffer() {
        let shoff = 0x40u64;
        let mut e = elf_with(3, 2, shoff);
        // Make the shstrtab point somewhere sane, then give section 2 (a symtab)
        // an enormous sh_size.
        let strtab_hdr = (shoff + 64 * 2) as usize;
        e[strtab_hdr + 24..strtab_hdr + 32].copy_from_slice(&0u64.to_le_bytes());
        e[strtab_hdr + 32..strtab_hdr + 40].copy_from_slice(&1u64.to_le_bytes());
        e[strtab_hdr..strtab_hdr + 4].copy_from_slice(&0u32.to_le_bytes());
        e[0x40 + 24..0x40 + 32].copy_from_slice(&0u64.to_le_bytes());
        e[0x40 + 32..0x40 + 40].copy_from_slice(&1u64.to_le_bytes());
        // symtab: sh_type = 2 (SYMTAB), huge size
        e[shoff as usize + 64 * 2 + 4..shoff as usize + 64 * 2 + 8]
            .copy_from_slice(&2u32.to_le_bytes());
        assert_returns_err(&e, "symtab extending past the buffer");
    }

    /// (e) the relocation scan ignored the declared sh_entsize while reading a
    /// fixed 16 bytes, so a bogus small non-zero entry_size both misparsed and
    /// ran off the section.
    #[test]
    fn test_parse_elf_rejects_short_rel_entsize() {
        let src = include_str!("loader.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod elf_range_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);
        let at = prod
            .find("relocation entry size below 16")
            .expect("the entsize guard");
        let block = &prod[at.saturating_sub(220)..(at + 60).min(prod.len())];
        assert!(
            block.contains("entry_size < 16"),
            "a relocation entry smaller than the 16 bytes the parser reads must \\
             be refused rather than misparsed"
        );
    }

    /// The positive control: a well-formed object with no usable sections must
    /// still be rejected cleanly (no sockops section), proving the guards did
    /// not turn every input into an error.
    #[test]
    fn test_valid_but_empty_elf_is_rejected_cleanly() {
        let e = elf_with(2, 1, 0x40);
        assert_returns_err(&e, "well-formed ELF with no sockops section");
    }

    /// Regression guards: the four checks the audit named must all be present.
    #[test]
    fn test_all_five_sites_are_guarded() {
        let src = include_str!("loader.rs");
        let prod = src
            .split_once("\n#[cfg(test)]\nmod elf_range_tests")
            .map(|(p, _)| p)
            .unwrap_or(src);
        assert!(prod.contains("e_shstrndx out of range"), "(a)");
        assert!(
            prod.contains("let region = |off: usize, size: usize|"),
            "region helper"
        );
        assert!(
            prod.contains("section extent overflow"),
            "checked_add in region"
        );
        assert!(
            prod.contains("strtab extent overflow"),
            "(c) strtab fallback"
        );
        assert!(
            prod.contains("relocation entry size below 16"),
            "(e) entsize"
        );
        assert!(
            !prod.contains("&elf_bytes[str_off..str_off + str_size]"),
            "(c) the unchecked strtab slice must be gone"
        );
        assert!(
            !prod.contains("elf_bytes[s_off..s_off + 4].try_into().unwrap()"),
            "(d) the unchecked symtab read must be gone"
        );
        assert!(
            !prod.contains("elf_bytes[r_off..r_off + 8].try_into().unwrap()"),
            "(e) the unchecked relocation read must be gone"
        );
    }
}
