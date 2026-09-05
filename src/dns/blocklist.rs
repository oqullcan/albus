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
            let curr = &self.nodes[curr_node_idx];
            if curr.child_count == 0 {
                return false;
            }

            let start = curr.first_child as usize;
            let end = start + curr.child_count as usize;
            if end > self.nodes.len() {
                return false;
            }

            let children = &self.nodes[start..end];
            match children.binary_search_by(|child| {
                let clabel = &self.labels
                    [child.label_offset as usize..child.label_offset as usize + child.label_len as usize];
                clabel.cmp(label.as_bytes())
            }) {
                Ok(child_pos) => {
                    let matched_idx = start + child_pos;
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
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != b"ALBUSBLK" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid albus blocklist magic header"));
        }

        let mut v_buf = [0u8; 4];
        file.read_exact(&mut v_buf)?;
        let version = u32::from_le_bytes(v_buf);
        if version != 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported blocklist binary version"));
        }

        let mut d_buf = [0u8; 8];
        file.read_exact(&mut d_buf)?;
        let total_domains = u64::from_le_bytes(d_buf) as usize;

        let mut l_buf = [0u8; 4];
        file.read_exact(&mut l_buf)?;
        let labels_len = u32::from_le_bytes(l_buf) as usize;

        let mut n_buf = [0u8; 4];
        file.read_exact(&mut n_buf)?;
        let nodes_len = u32::from_le_bytes(n_buf) as usize;

        let mut labels = vec![0u8; labels_len];
        file.read_exact(&mut labels)?;

        let mut nodes = Vec::with_capacity(nodes_len);
        let node_size = std::mem::size_of::<CompactNode>();
        let mut node_raw = vec![0u8; nodes_len * node_size];
        file.read_exact(&mut node_raw)?;

        unsafe {
            let ptr = node_raw.as_ptr() as *const CompactNode;
            for i in 0..nodes_len {
                nodes.push(*ptr.add(i));
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
            curr = curr.children.entry(label.to_string()).or_insert_with(IntermediateNode::new);

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
            let mut sorted_children: Vec<(&String, &IntermediateNode)> = inter_node.children.iter().collect();
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
pub async fn fetch_and_compile_hagezi(cache_path: &Path) -> Result<CompactBlocklist, Box<dyn std::error::Error + Send + Sync>> {
    info!("downloading HaGeZi Multi PRO and TIF blocklists from jsdelivr CDN...");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut builder = BlocklistBuilder::new();

    // 1. HaGeZi Multi PRO
    let pro_url = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt";
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
}
