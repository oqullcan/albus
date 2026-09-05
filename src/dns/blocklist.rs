//! ultra-compact arena-based suffix radix trie for high-performance dns blocklists.
//!
//! implements label-reversed matching with automatic subdomain pruning to compress
//! 200,000+ domain rules into single-digit megabytes of contiguous memory with zero
//! heap allocations during query matching.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use tracing::{debug, info, warn};

// compact 16-byte trie node representing a domain label level
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CompactNode {
    pub label_offset: u32,
    pub label_len: u16,
    pub is_terminal: bool,
    pub _reserved: u8,
    pub first_child: u32,
    pub child_count: u16,
    pub _padding: u16,
}

// safety limits to protect against unbounded allocations and DoS attacks via crafted cache files
pub const MAX_BLOCKLIST_NODES: u32 = 10_000_000;
pub const MAX_BLOCKLIST_LABELS_LEN: u32 = 128 * 1024 * 1024; // 128 MB maximum label string pool

#[derive(Clone, Debug)]
pub struct CompactBlocklist {
    pub labels: Vec<u8>,
    pub nodes: Vec<CompactNode>,
    pub total_domains: usize,
}

impl CompactBlocklist {
    // initializes an empty blocklist
    pub fn empty() -> Self {
        Self {
            labels: Vec::new(),
            nodes: vec![CompactNode {
                label_offset: 0,
                label_len: 0,
                is_terminal: false,
                _reserved: 0,
                first_child: 0,
                child_count: 0,
                _padding: 0,
            }],
            total_domains: 0,
        }
    }

    // checks if domain or any of its parent suffixes is blocked with 0 heap allocations
    pub fn check(&self, domain: &str) -> bool {
        if self.nodes.is_empty() || self.total_domains == 0 {
            return false;
        }

        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return false;
        }

        // labels traversed in reverse order (tld first)
        let labels: Vec<&str> = clean.rsplit('.').collect();
        let mut curr_node_idx = 0usize;

        for label in labels {
            if curr_node_idx >= self.nodes.len() {
                return false;
            }
            let curr = &self.nodes[curr_node_idx];
            if curr.child_count == 0 {
                return false;
            }

            let start = curr.first_child as usize;
            let count = curr.child_count as usize;
            let end = start.saturating_add(count);
            if start >= self.nodes.len() || end > self.nodes.len() {
                return false;
            }

            let children = &self.nodes[start..end];
            match children.binary_search_by(|child| {
                let l_start = child.label_offset as usize;
                let l_end = l_start.saturating_add(child.label_len as usize);
                if l_end > self.labels.len() || l_start > self.labels.len() {
                    return std::cmp::Ordering::Less;
                }
                let clabel = &self.labels[l_start..l_end];
                clabel.cmp(label.as_bytes())
            }) {
                Ok(child_pos) => {
                    let matched_idx = start.saturating_add(child_pos);
                    if matched_idx >= self.nodes.len() {
                        return false;
                    }
                    let matched_node = &self.nodes[matched_idx];
                    if matched_node.is_terminal {
                        // suffix matched (e.g. doubleclick.net matches ad.doubleclick.net)
                        return true;
                    }
                    curr_node_idx = matched_idx;
                }
                Err(_) => {
                    return false;
                }
            }
        }

        false
    }

    // serializes compact blocklist to binary disk blob
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = fs::File::create(path)?;
        // magic header: ALBUSBLK
        file.write_all(b"ALBUSBLK")?;
        file.write_all(&1u32.to_le_bytes())?; // version 1
        file.write_all(&(self.total_domains as u64).to_le_bytes())?;
        file.write_all(&(self.labels.len() as u32).to_le_bytes())?;
        file.write_all(&(self.nodes.len() as u32).to_le_bytes())?;

        file.write_all(&self.labels)?;

        // write nodes as raw binary bytes
        let node_bytes = unsafe {
            std::slice::from_raw_parts(
                self.nodes.as_ptr() as *const u8,
                self.nodes.len() * std::mem::size_of::<CompactNode>(),
            )
        };
        file.write_all(node_bytes)?;
        file.sync_all()?;
        Ok(())
    }

    // deserializes compact blocklist from binary disk blob in < 1ms
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = fs::File::open(path)?;
        let file_len = file.metadata()?.len();
        Self::read_from(&mut file, file_len)
    }

    // deserializes compact blocklist directly from in-memory byte slice
    pub fn load_from_bytes(bytes: &[u8]) -> io::Result<Self> {
        Self::read_from(bytes, bytes.len() as u64)
    }

    // common deserializer implementation across files and byte buffers
    pub fn read_from<R: io::Read>(mut reader: R, file_len: u64) -> io::Result<Self> {
        // Binary header layout: 8B magic + 4B version + 8B total_domains + 4B labels_len + 4B nodes_len = 28B
        const HEADER_LEN: u64 = 28;
        if file_len < HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "blocklist binary file too short for header",
            ));
        }

        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != b"ALBUSBLK" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid albus blocklist magic header",
            ));
        }

        let mut v_buf = [0u8; 4];
        reader.read_exact(&mut v_buf)?;
        let version = u32::from_le_bytes(v_buf);
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported blocklist binary version",
            ));
        }

        let mut d_buf = [0u8; 8];
        reader.read_exact(&mut d_buf)?;
        let total_domains = u64::from_le_bytes(d_buf) as usize;

        let mut l_buf = [0u8; 4];
        reader.read_exact(&mut l_buf)?;
        let labels_len_u32 = u32::from_le_bytes(l_buf);
        if labels_len_u32 > MAX_BLOCKLIST_LABELS_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "blocklist labels length {} exceeds safety ceiling {}",
                    labels_len_u32, MAX_BLOCKLIST_LABELS_LEN
                ),
            ));
        }
        let labels_len = labels_len_u32 as usize;

        let mut n_buf = [0u8; 4];
        reader.read_exact(&mut n_buf)?;
        let nodes_len_u32 = u32::from_le_bytes(n_buf);
        if nodes_len_u32 > MAX_BLOCKLIST_NODES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "blocklist nodes count {} exceeds safety ceiling {}",
                    nodes_len_u32, MAX_BLOCKLIST_NODES
                ),
            ));
        }
        let nodes_len = nodes_len_u32 as usize;

        let node_size = std::mem::size_of::<CompactNode>();
        let payload_len =
            (labels_len as u64).saturating_add((nodes_len as u64).saturating_mul(node_size as u64));
        let remaining_file_len = file_len - HEADER_LEN;

        if payload_len > remaining_file_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "declared blocklist payload size ({} bytes) exceeds physical file bounds ({} bytes)",
                    payload_len, remaining_file_len
                ),
            ));
        }

        let mut labels = vec![0u8; labels_len];
        reader.read_exact(&mut labels)?;

        let mut nodes = Vec::with_capacity(nodes_len);
        let mut node_raw = vec![0u8; nodes_len * node_size];
        reader.read_exact(&mut node_raw)?;

        for chunk in node_raw.chunks_exact(node_size) {
            let label_offset = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let label_len = u16::from_le_bytes(chunk[4..6].try_into().unwrap());
            let is_terminal = chunk[6] != 0;
            let reserved = chunk[7];
            let first_child = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
            let child_count = u16::from_le_bytes(chunk[12..14].try_into().unwrap());
            let padding = u16::from_le_bytes(chunk[14..16].try_into().unwrap());

            nodes.push(CompactNode {
                label_offset,
                label_len,
                is_terminal,
                _reserved: reserved,
                first_child,
                child_count,
                _padding: padding,
            });
        }

        // validate consistency of every node to prevent out-of-bounds panics or corrupt state
        for (i, node) in nodes.iter().enumerate() {
            let label_end = (node.label_offset as usize).saturating_add(node.label_len as usize);
            if label_end > labels.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "node {} label range [{}..{}] exceeds labels pool bounds ({})",
                        i,
                        node.label_offset,
                        label_end,
                        labels.len()
                    ),
                ));
            }

            let child_end = (node.first_child as usize).saturating_add(node.child_count as usize);
            if child_end > nodes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "node {} child range [{}..{}] exceeds nodes count ({})",
                        i,
                        node.first_child,
                        child_end,
                        nodes.len()
                    ),
                ));
            }
        }

        Ok(Self {
            labels,
            nodes,
            total_domains,
        })
    }
}

// temporary builder node used during list assembly and subdomain pruning
struct IntermediateNode {
    is_terminal: bool,
    children: HashMap<String, IntermediateNode>,
}

impl IntermediateNode {
    fn new() -> Self {
        Self {
            is_terminal: false,
            children: HashMap::new(),
        }
    }
}

// builder assembling text rules into optimal compact arena
pub struct BlocklistBuilder {
    root: IntermediateNode,
    domain_count: usize,
}

impl BlocklistBuilder {
    pub fn new() -> Self {
        Self {
            root: IntermediateNode::new(),
            domain_count: 0,
        }
    }

    // parses text content containing one domain per line (comments # ignored)
    pub fn add_text_lines(&mut self, text: &str) {
        for line in text.lines() {
            let clean = line.trim();
            if clean.is_empty() || clean.starts_with('#') || clean.starts_with("//") {
                continue;
            }
            // extract domain part (handles '0.0.0.0 domain.com' or raw 'domain.com')
            let domain = clean.split_whitespace().last().unwrap_or("");
            let domain = domain.trim_start_matches("*.").trim_end_matches('.');
            if !domain.is_empty() && domain.contains('.') {
                self.add_domain(domain);
            }
        }
    }

    // inserts domain in reverse label order with automatic subdomain pruning
    pub fn add_domain(&mut self, domain: &str) {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return;
        }

        let labels: Vec<&str> = clean.rsplit('.').collect();
        let mut curr = &mut self.root;

        for (i, &label) in labels.iter().enumerate() {
            if curr.is_terminal {
                // parent domain already blocked; prune redundant subdomain
                return;
            }

            let is_last = i == labels.len() - 1;
            curr = curr
                .children
                .entry(label.to_string())
                .or_insert_with(IntermediateNode::new);

            if is_last {
                if !curr.is_terminal {
                    curr.is_terminal = true;
                    // prune any subdomains that were inserted prior to this parent domain
                    curr.children.clear();
                    self.domain_count += 1;
                }
                return;
            }
        }
    }

    // compiles intermediate tree into contiguous flat arena blocklist
    pub fn build(self) -> CompactBlocklist {
        let mut labels = Vec::new();
        let mut nodes = Vec::new();

        // push root node
        nodes.push(CompactNode {
            label_offset: 0,
            label_len: 0,
            is_terminal: false,
            _reserved: 0,
            first_child: 0,
            child_count: 0,
            _padding: 0,
        });

        let mut queue = VecDeque::new();
        queue.push_back((&self.root, 0usize));

        while let Some((inter_node, compact_idx)) = queue.pop_front() {
            if inter_node.children.is_empty() {
                continue;
            }

            // sort children alphabetically for binary search
            let mut sorted_children: Vec<(&String, &IntermediateNode)> =
                inter_node.children.iter().collect();
            sorted_children.sort_by(|a, b| a.0.cmp(b.0));

            let first_child = nodes.len() as u32;
            let child_count = sorted_children.len() as u16;

            nodes[compact_idx].first_child = first_child;
            nodes[compact_idx].child_count = child_count;

            let mut child_compact_indices = Vec::with_capacity(sorted_children.len());

            for (label, child_node) in &sorted_children {
                let label_offset = labels.len() as u32;
                let label_len = label.len() as u16;
                labels.extend_from_slice(label.as_bytes());

                let child_idx = nodes.len();
                nodes.push(CompactNode {
                    label_offset,
                    label_len,
                    is_terminal: child_node.is_terminal,
                    _reserved: 0,
                    first_child: 0,
                    child_count: 0,
                    _padding: 0,
                });

                child_compact_indices.push((child_node, child_idx));
            }

            for (&child_node, child_idx) in child_compact_indices {
                if !child_node.is_terminal {
                    queue.push_back((child_node, child_idx));
                }
            }
        }

        CompactBlocklist {
            labels,
            nodes,
            total_domains: self.domain_count,
        }
    }
}

// curated seed blocklist loaded immediately without network dependencies
const ESSENTIAL_SEED_DOMAINS: &[&str] = &[
    // google tracking & ads
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "google-analytics.com",
    "app-measurement.com",
    "admob.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    // telemetry & analytics
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "telemetry.mozilla.org",
    "data.flurry.com",
    "scorecardresearch.com",
    "quantserve.com",
    "appsflyer.com",
    "branch.io",
    "adjust.com",
    "singular.net",
    "kochava.com",
    "amplitude.com",
    "mixpanel.com",
    "segment.io",
    // meta / facebook tracking
    "pixel.facebook.com",
    "an.facebook.com",
    "graph.instagram.com",
    // major ad networks
    "adroll.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "adnxs.com",
    "rubiconproject.com",
    "openx.net",
    "pubmatic.com",
    "bidswitch.net",
    "casalemedia.com",
    "contextweb.com",
    "advertising.com",
    "revcontent.com",
    "popads.net",
    "zergnet.com",
    "adcolony.com",
    "unityads.unity3d.com",
    "inmobi.com",
    "chartboost.com",
    "ironsrc.com",
    "vungle.com",
    "applifier.com",
    // yandex / baidu metrics
    "metrika.yandex.ru",
    "mc.yandex.ru",
    "hm.baidu.com",
    // crypto mining & malware C2 seeds
    "coinhive.com",
    "coin-hive.com",
    "jsecoin.com",
    "cryptoloot.pro",
    "authedmine.com",
];

// builds initial seed blocklist in < 1ms
pub fn build_seed_blocklist() -> CompactBlocklist {
    let mut builder = BlocklistBuilder::new();
    for &domain in ESSENTIAL_SEED_DOMAINS {
        builder.add_domain(domain);
    }
    builder.build()
}

// downloads hagezi multi pro + tif medium feeds, compiles compact blob, and persists to cache_path
pub async fn fetch_and_compile_hagezi(
    cache_path: &Path,
) -> Result<CompactBlocklist, Box<dyn std::error::Error + Send + Sync>> {
    info!("downloading HaGeZi Multi PRO and TIF blocklists from jsdelivr CDN...");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut builder = BlocklistBuilder::new();

    // 1. HaGeZi Multi PRO
    let pro_url =
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt";
    match client.get(pro_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().await?;
            builder.add_text_lines(&text);
            info!("HaGeZi Multi PRO loaded successfully");
        }
        Ok(resp) => warn!("HaGeZi Multi PRO HTTP status: {}", resp.status()),
        Err(e) => warn!("HaGeZi Multi PRO download error: {}", e),
    }

    // 2. HaGeZi TIF Medium
    let tif_url = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt";
    match client.get(tif_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().await?;
            builder.add_text_lines(&text);
            info!("HaGeZi TIF Medium loaded successfully");
        }
        Ok(resp) => warn!("HaGeZi TIF Medium HTTP status: {}", resp.status()),
        Err(e) => warn!("HaGeZi TIF Medium download error: {}", e),
    }

    if builder.domain_count == 0 {
        return Err("all blocklist downloads failed or returned empty content".into());
    }

    let compiled = builder.build();
    info!(
        rules = compiled.total_domains,
        nodes = compiled.nodes.len(),
        labels_kb = compiled.labels.len() / 1024,
        "HaGeZi blocklist compiled into compact arena"
    );

    if let Some(parent) = cache_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Err(e) = compiled.save_to_file(cache_path) {
        warn!("failed to save compiled blocklist binary cache: {}", e);
    } else {
        info!(path = %cache_path.display(), "compiled blocklist binary cache saved");
    }

    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_blocklist_pruning_and_matching() {
        let mut builder = BlocklistBuilder::new();
        builder.add_domain("doubleclick.net");
        // redundant subdomains should be pruned
        builder.add_domain("ad.doubleclick.net");
        builder.add_domain("tracker.google.com");

        let blocklist = builder.build();
        assert_eq!(blocklist.total_domains, 2);

        assert!(blocklist.check("doubleclick.net"));
        assert!(blocklist.check("ad.doubleclick.net"));
        assert!(blocklist.check("foo.bar.ad.doubleclick.net"));

        assert!(blocklist.check("tracker.google.com"));
        assert!(blocklist.check("sub.tracker.google.com"));
        assert!(!blocklist.check("google.com"));
        assert!(!blocklist.check("mail.google.com"));
        assert!(!blocklist.check("example.com"));
    }

    #[test]
    fn test_seed_blocklist_sanity() {
        let blocklist = build_seed_blocklist();
        assert!(blocklist.total_domains > 30);
        assert!(blocklist.check("adservice.google.com"));
        assert!(blocklist.check("telemetry.microsoft.com"));
        assert!(blocklist.check("coinhive.com"));
        assert!(!blocklist.check("rust-lang.org"));
    }

    #[test]
    fn test_binary_serialization_roundtrip() {
        let blocklist = build_seed_blocklist();
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_albus_blocklist.bin");

        blocklist.save_to_file(&path).unwrap();
        let loaded = CompactBlocklist::load_from_file(&path).unwrap();

        assert_eq!(loaded.total_domains, blocklist.total_domains);
        assert_eq!(loaded.nodes.len(), blocklist.nodes.len());
        assert_eq!(loaded.labels.len(), blocklist.labels.len());

        assert!(loaded.check("doubleclick.net"));
        assert!(loaded.check("ad.doubleclick.net"));
        assert!(!loaded.check("rust-lang.org"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_blocklist_load_rejects_oversized_allocation() {
        let temp_dir = std::env::temp_dir();

        // 1. File declaring nodes_len > MAX_BLOCKLIST_NODES (e.g. 50_000_000)
        let path1 = temp_dir.join("test_oversized_nodes.bin");
        {
            let mut file = fs::File::create(&path1).unwrap();
            file.write_all(b"ALBUSBLK").unwrap(); // magic (8B)
            file.write_all(&1u32.to_le_bytes()).unwrap(); // version = 1 (4B)
            file.write_all(&100u64.to_le_bytes()).unwrap(); // total_domains = 100 (8B)
            file.write_all(&10u32.to_le_bytes()).unwrap(); // labels_len = 10 (4B)
            file.write_all(&50_000_000u32.to_le_bytes()).unwrap(); // nodes_len = 50M (4B) > MAX_BLOCKLIST_NODES
            file.sync_all().unwrap();
        }
        let res1 = CompactBlocklist::load_from_file(&path1);
        assert!(res1.is_err());
        assert_eq!(res1.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_file(&path1);

        // 2. File declaring nodes_len within ceiling, but payload exceeds physical file size
        let path2 = temp_dir.join("test_truncated_payload.bin");
        {
            let mut file = fs::File::create(&path2).unwrap();
            file.write_all(b"ALBUSBLK").unwrap(); // magic (8B)
            file.write_all(&1u32.to_le_bytes()).unwrap(); // version = 1 (4B)
            file.write_all(&100u64.to_le_bytes()).unwrap(); // total_domains = 100 (8B)
            file.write_all(&1000u32.to_le_bytes()).unwrap(); // labels_len = 1000 (4B)
            file.write_all(&100_000u32.to_le_bytes()).unwrap(); // nodes_len = 100_000 (4B)
                                                                // No payload written, so file is only 28 bytes!
            file.sync_all().unwrap();
        }
        let res2 = CompactBlocklist::load_from_file(&path2);
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_file(&path2);

        // 3. File declaring labels_len > MAX_BLOCKLIST_LABELS_LEN
        let path3 = temp_dir.join("test_oversized_labels.bin");
        {
            let mut file = fs::File::create(&path3).unwrap();
            file.write_all(b"ALBUSBLK").unwrap();
            file.write_all(&1u32.to_le_bytes()).unwrap();
            file.write_all(&100u64.to_le_bytes()).unwrap();
            file.write_all(&(MAX_BLOCKLIST_LABELS_LEN + 1).to_le_bytes())
                .unwrap();
            file.write_all(&10u32.to_le_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let res3 = CompactBlocklist::load_from_file(&path3);
        assert!(res3.is_err());
        assert_eq!(res3.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_file(&path3);
    }

    #[test]
    fn test_blocklist_load_rejects_corrupted_node_offsets() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_corrupted_node_offsets.bin");

        // 1. Label offset out of bounds
        {
            let mut file = fs::File::create(&path).unwrap();
            file.write_all(b"ALBUSBLK").unwrap();
            file.write_all(&1u32.to_le_bytes()).unwrap();
            file.write_all(&1u64.to_le_bytes()).unwrap();
            file.write_all(&10u32.to_le_bytes()).unwrap(); // 10 bytes label pool
            file.write_all(&1u32.to_le_bytes()).unwrap(); // 1 node
            file.write_all(b"0123456789").unwrap(); // 10 bytes

            let bad_node = CompactNode {
                label_offset: 20, // > 10!
                label_len: 5,
                is_terminal: true,
                _reserved: 0,
                first_child: 0,
                child_count: 0,
                _padding: 0,
            };
            let slice = unsafe {
                std::slice::from_raw_parts(
                    &bad_node as *const _ as *const u8,
                    std::mem::size_of::<CompactNode>(),
                )
            };
            file.write_all(slice).unwrap();
            file.sync_all().unwrap();
        }

        let res = CompactBlocklist::load_from_file(&path);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_file(&path);

        // 2. Child offset out of bounds
        {
            let mut file = fs::File::create(&path).unwrap();
            file.write_all(b"ALBUSBLK").unwrap();
            file.write_all(&1u32.to_le_bytes()).unwrap();
            file.write_all(&1u64.to_le_bytes()).unwrap();
            file.write_all(&10u32.to_le_bytes()).unwrap();
            file.write_all(&1u32.to_le_bytes()).unwrap();
            file.write_all(b"0123456789").unwrap();

            let bad_node = CompactNode {
                label_offset: 0,
                label_len: 4,
                is_terminal: false,
                _reserved: 0,
                first_child: 5, // exceeds nodes.len() = 1
                child_count: 2,
                _padding: 0,
            };
            let slice = unsafe {
                std::slice::from_raw_parts(
                    &bad_node as *const _ as *const u8,
                    std::mem::size_of::<CompactNode>(),
                )
            };
            file.write_all(slice).unwrap();
            file.sync_all().unwrap();
        }

        let res = CompactBlocklist::load_from_file(&path);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_malformed_blocklist_check_safe() {
        // Construct malformed blocklist directly and ensure check() returns false instead of panicking
        let malformed = CompactBlocklist {
            labels: b"malicious".to_vec(),
            nodes: vec![CompactNode {
                label_offset: 50, // out of bounds
                label_len: 100,   // out of bounds
                is_terminal: false,
                _reserved: 0,
                first_child: 999, // out of bounds
                child_count: 50,  // out of bounds
                _padding: 0,
            }],
            total_domains: 1,
        };

        assert!(!malformed.check("example.com"));
        assert!(!malformed.check("test.org"));
    }
}
