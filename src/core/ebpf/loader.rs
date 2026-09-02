//! direct linux ebpf elf parser, map creation, cgroup sock_ops attachment, and perf ring buffer poller.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use tracing::{debug, info, warn};

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
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
#[derive(Debug, Clone, Copy, Default)]
pub struct RawConnEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
}

// runtime configuration struct mirrored to ebpf array map
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BpfConfig {
    pub mss: u16,
    pub restore_mss: u16,
    pub restore_after_bytes: u32,
    pub enabled: u8,
    pub reserved: [u8; 7],
}

impl BpfConfig {
    pub fn new(mss: u16, restore_mss: u16, restore_after_bytes: u32, enabled: bool) -> Self {
        Self {
            mss,
            restore_mss,
            restore_after_bytes,
            enabled: if enabled { 1 } else { 0 },
            reserved: [0; 7],
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
    pub conn_events_fd: RawFd,
    pub connections_fd: RawFd,
    pub perf_readers: Vec<PerfReader>,
    pub attached: bool,
}

impl BpfEngine {
    // loads embedded elf bytecode, creates bpf maps, relocates symbols, and attaches to cgroup v2
    pub fn load_and_attach(cgroup_path: &str) -> Result<Self> {
        let elf_bytes = include_bytes!(env!("ALBUS_BPF_BYTECODE"));
        let num_cpus = get_possible_cpus().max(1);

        // 1. initialize ebpf kernel maps
        let config_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, 4, std::mem::size_of::<BpfConfig>() as u32, 1, "config_map")?;
        let target_ports_fd = bpf_create_map(BPF_MAP_TYPE_HASH, 2, 1, 64, "target_ports")?;
        let exclude_ips_fd = bpf_create_map(BPF_MAP_TYPE_HASH, 4, 1, 64, "exclude_ips")?;
        let conn_events_fd = bpf_create_map(BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, (num_cpus.max(128)) as u32, "conn_events")?;
        let connections_fd = bpf_create_map(BPF_MAP_TYPE_LRU_HASH, 8, 8, 65536, "connections")?;

        let mut map_fds = HashMap::new();
        map_fds.insert("config_map".to_string(), config_map_fd);
        map_fds.insert("target_ports".to_string(), target_ports_fd);
        map_fds.insert("exclude_ips".to_string(), exclude_ips_fd);
        map_fds.insert("conn_events".to_string(), conn_events_fd);
        map_fds.insert("connections".to_string(), connections_fd);

        // 2. parse elf section headers and relocate pseudo map file descriptors
        let insns = parse_elf_sockops(elf_bytes, &map_fds)?;

        // 3. submit instructions to in-kernel bpf verifier
        let prog_fd = bpf_load_program(BPF_PROG_TYPE_SOCK_OPS, &insns, "albus_sockops")?;

        // 4. open cgroup hierarchy directory handle and attach program
        let cgroup_file = File::open(cgroup_path)
            .map_err(|e| Error::other(format!("failed to open cgroup path {}: {}", cgroup_path, e)))?;
        let cgroup_fd = cgroup_file.as_raw_fd();
        std::mem::forget(cgroup_file); // maintain file descriptor lifecycle

        bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS)?;

        // 5. allocate memory-mapped perf event ring buffers for each available cpu core
        let mut perf_readers = Vec::new();
        for cpu in 0..num_cpus {
            match PerfReader::new(cpu as i32) {
                Ok(reader) => {
                    let key = cpu as u32;
                    let val = reader.fd as u32;
                    if let Err(e) = bpf_map_update(conn_events_fd, &key, &val) {
                        warn!("bpf_map_update conn_events on cpu {}: {}", cpu, e);
                    }
                    perf_readers.push(reader);
                }
                Err(e) => {
                    debug!("could not attach perf event on cpu {}: {}", cpu, e);
                }
            }
        }

        info!(cgroup = %cgroup_path, cpus = perf_readers.len(), "eBPF sock_ops attached successfully");

        Ok(Self {
            prog_fd,
            cgroup_fd,
            config_map_fd,
            target_ports_fd,
            exclude_ips_fd,
            conn_events_fd,
            connections_fd,
            perf_readers,
            attached: true,
        })
    }

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

    // inserts destination ips into exclusion map to bypass packet fragmentation
    pub fn push_exclude_ips(&self, ips: &[Ipv4Addr]) -> Result<()> {
        let val = 1u8;
        for ip in ips {
            let key = u32::from_ne_bytes(ip.octets());
            bpf_map_update(self.exclude_ips_fd, &key, &val)?;
        }
        Ok(())
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

fn bpf_create_map(map_type: u32, key_size: u32, value_size: u32, max_entries: u32, name: &str) -> Result<RawFd> {
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

    let res = sys_bpf(BPF_MAP_CREATE, &attr as *const _ as *const libc::c_void, std::mem::size_of::<BpfAttrMap>());
    if res < 0 {
        Err(Error::other(format!("bpf(BPF_MAP_CREATE, {}) failed: {}", name, Error::last_os_error())))
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

    let res = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr as *const _ as *const libc::c_void, std::mem::size_of::<BpfAttrMapElem>());
    if res < 0 {
        Err(Error::other(format!("bpf(BPF_MAP_UPDATE_ELEM) failed: {}", Error::last_os_error())))
    } else {
        Ok(())
    }
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

    let res = sys_bpf(BPF_PROG_LOAD, &attr as *const _ as *const libc::c_void, std::mem::size_of::<BpfAttrProg>());
    if res < 0 {
        let log = String::from_utf8_lossy(&log_buf);
        let cleaned_log = log.trim_matches(char::from(0));
        Err(Error::other(format!("bpf(BPF_PROG_LOAD) failed: {}\nBPF Verifier log:\n{}", Error::last_os_error(), cleaned_log)))
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

    let res = sys_bpf(BPF_PROG_ATTACH, &attr as *const _ as *const libc::c_void, std::mem::size_of::<BpfAttrAttach>());
    if res < 0 {
        Err(Error::other(format!("bpf(BPF_PROG_ATTACH) failed: {}", Error::last_os_error())))
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

    let res = sys_bpf(BPF_PROG_DETACH, &attr as *const _ as *const libc::c_void, std::mem::size_of::<BpfAttrDetach>());
    if res < 0 {
        Err(Error::other(format!("bpf(BPF_PROG_DETACH) failed: {}", Error::last_os_error())))
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
pub fn parse_elf_sockops(elf_bytes: &[u8], map_fds: &HashMap<String, RawFd>) -> Result<Vec<BpfInsn>> {
    if elf_bytes.len() < 64 || &elf_bytes[0..4] != b"\x7FELF" {
        return Err(Error::new(ErrorKind::InvalidData, "invalid ELF binary format"));
    }

    let e_shoff = u64::from_le_bytes(elf_bytes[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(elf_bytes[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(elf_bytes[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(elf_bytes[62..64].try_into().unwrap()) as usize;

    if e_shoff + (e_shnum * e_shentsize) > elf_bytes.len() {
        return Err(Error::new(ErrorKind::InvalidData, "ELF section header table out of bounds"));
    }

    let shstrtab_hdr_offset = e_shoff + (e_shstrndx * e_shentsize);
    let shstrtab_offset = u64::from_le_bytes(elf_bytes[shstrtab_hdr_offset + 24..shstrtab_hdr_offset + 32].try_into().unwrap()) as usize;
    let shstrtab_size = u64::from_le_bytes(elf_bytes[shstrtab_hdr_offset + 32..shstrtab_hdr_offset + 40].try_into().unwrap()) as usize;
    let shstrtab = &elf_bytes[shstrtab_offset..shstrtab_offset + shstrtab_size];

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
        let sh_name_off = u32::from_le_bytes(elf_bytes[sh_offset..sh_offset + 4].try_into().unwrap()) as usize;
        let sh_type = u32::from_le_bytes(elf_bytes[sh_offset + 4..sh_offset + 8].try_into().unwrap());
        let sh_offset_val = u64::from_le_bytes(elf_bytes[sh_offset + 24..sh_offset + 32].try_into().unwrap()) as usize;
        let sh_size = u64::from_le_bytes(elf_bytes[sh_offset + 32..sh_offset + 40].try_into().unwrap()) as usize;
        let sh_link = u32::from_le_bytes(elf_bytes[sh_offset + 40..sh_offset + 44].try_into().unwrap()) as usize;
        let sh_entsize_val = u64::from_le_bytes(elf_bytes[sh_offset + 56..sh_offset + 64].try_into().unwrap()) as usize;

        let name = get_sh_name(sh_name_off);

        if name == "sockops" || (sh_type == 1 && name.contains("sockops")) {
            sockops_section = Some((i, sh_offset_val, sh_size));
        } else if sh_type == 2 || name == ".symtab" {
            symtab_section = Some((sh_offset_val, sh_size, sh_link));
        } else if sh_type == 3 && (name == ".strtab" || (strtab_section.is_none() && i == 1)) {
            strtab_section = Some((sh_offset_val, sh_size));
        } else if (sh_type == 4 || sh_type == 9) && (name == ".relsockops" || name == ".rel.sockops" || name == ".relasockops" || name == ".rela.sockops") {
            let ent_size = if sh_entsize_val > 0 { sh_entsize_val } else if sh_type == 4 { 24 } else { 16 };
            rel_section = Some((sh_type, sh_offset_val, sh_size, ent_size));
        }
    }

    let (_, code_offset, code_size) = sockops_section
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "could not find 'sockops' program section in BPF ELF"))?;

    let code_bytes = &elf_bytes[code_offset..code_offset + code_size];
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
    if let (Some((sym_off, sym_size, sym_link)), Some((_, rel_off, rel_size, entry_size))) = (symtab_section, rel_section) {
        let strtab = if sym_link < e_shnum {
            let str_hdr = e_shoff + (sym_link * e_shentsize);
            let s_off = u64::from_le_bytes(elf_bytes[str_hdr + 24..str_hdr + 32].try_into().unwrap()) as usize;
            let s_size = u64::from_le_bytes(elf_bytes[str_hdr + 32..str_hdr + 40].try_into().unwrap()) as usize;
            if s_off + s_size <= elf_bytes.len() {
                &elf_bytes[s_off..s_off + s_size]
            } else {
                &[]
            }
        } else if let Some((str_off, str_size)) = strtab_section {
            &elf_bytes[str_off..str_off + str_size]
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

        let num_syms = sym_size / 24;
        let mut symbols = Vec::with_capacity(num_syms);
        for i in 0..num_syms {
            let s_off = sym_off + (i * 24);
            let st_name = u32::from_le_bytes(elf_bytes[s_off..s_off + 4].try_into().unwrap()) as usize;
            symbols.push(get_sym_name(st_name));
        }

        let num_rels = rel_size / entry_size;

        for i in 0..num_rels {
            let r_off = rel_off + (i * entry_size);
            let r_offset = u64::from_le_bytes(elf_bytes[r_off..r_off + 8].try_into().unwrap()) as usize;
            let r_info = u64::from_le_bytes(elf_bytes[r_off + 8..r_off + 16].try_into().unwrap());
            let sym_idx = (r_info >> 32) as usize;

            let insn_idx = r_offset / 8;
            if insn_idx < insns.len() && sym_idx < symbols.len() {
                let sym_name = &symbols[sym_idx];
                if let Some(&fd) = map_fds.get(sym_name) {
                    insns[insn_idx].dst_reg = (BPF_PSEUDO_MAP_FD << 4) | (insns[insn_idx].dst_reg & 0x0F);
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
        let num_pages = 8;
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
            unsafe { libc::close(fd); }
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
                    let event = unsafe { std::ptr::read(evt_bytes.as_ptr() as *const RawConnEvent) };
                    callback(event);
                }
            }

            tail += size as u64;
        }

        unsafe { std::ptr::write_volatile(&mut header.data_tail, tail); }
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
        map_fds.insert("target_ports".to_string(), 102);
        map_fds.insert("conn_events".to_string(), 103);
        map_fds.insert("connections".to_string(), 104);

        let insns = parse_elf_sockops(elf_bytes, &map_fds).expect("elf parsing should succeed");
        assert!(!insns.is_empty(), "instructions must not be empty");

        let imms: Vec<i32> = insns.iter().map(|i| i.imm).collect();
        assert!(imms.contains(&100), "config_map relocation (fd 100) must be applied");
        assert!(imms.contains(&101), "exclude_ips relocation (fd 101) must be applied");
        assert!(imms.contains(&102), "target_ports relocation (fd 102) must be applied");
        assert!(imms.contains(&103), "conn_events relocation (fd 103) must be applied");
        assert!(imms.contains(&104), "connections relocation (fd 104) must be applied");

        let conn_count = imms.iter().filter(|&&imm| imm == 104).count();
        assert_eq!(conn_count, 3, "connections map should be relocated 3 times in bpf bytecode");
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
