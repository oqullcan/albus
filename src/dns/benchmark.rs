//! automated resolver latency benchmarking and performance inspection engine.
//!
//! probes public and configured upstream resolvers (doh, dnscrypt, dot) concurrently,
//! measuring round-trip latency, packet loss, and dnssec validation capability.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use crate::app::config::Config;
use crate::dns::diagnostics::build_dns_query;
use crate::dns::doh::DoHResolver;
use crate::dns::dot::DotClient;
use crate::dns::sources::{RemoteResolverEntry, SourceManager};
use crate::dns::stamp::StampProtocol;

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub protocol: &'static str,
    pub endpoint: String,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    pub success_rate: f64,
    pub dnssec: bool,
    pub responsive: bool,
}

#[derive(Debug, Clone)]
pub struct BenchmarkOptions {
    pub domain: String,
    pub count: usize,
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub top: usize,
    pub protocol_filter: Option<String>,
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            domain: "example.com".to_string(),
            count: 3,
            timeout_secs: 2,
            concurrency: 16,
            top: 10,
            protocol_filter: None,
        }
    }
}

// probes a single doh upstream endpoint multiple times
async fn probe_doh(
    name: &str,
    endpoint: &str,
    query_bytes: &[u8],
    count: usize,
    timeout: Duration,
) -> BenchmarkResult {
    let mut latencies = Vec::new();
    let mut dnssec_detected = false;

    let resolver =
        match DoHResolver::new_with_options(endpoint, &[], false, false, None, None, None) {
            Ok(r) => r,
            Err(_) => {
                return BenchmarkResult {
                    name: name.to_string(),
                    protocol: "DoH",
                    endpoint: endpoint.to_string(),
                    min_ms: 0.0,
                    avg_ms: 0.0,
                    max_ms: 0.0,
                    success_rate: 0.0,
                    dnssec: false,
                    responsive: false,
                };
            }
        };

    for _ in 0..count {
        let start = Instant::now();
        match tokio::time::timeout(timeout, resolver.resolve(query_bytes)).await {
            Ok(Ok((resp, _))) => {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                latencies.push(ms);
                // check AD bit (bit 5 in byte 3) indicating authentic data (DNSSEC)
                if resp.len() >= 4 && (resp[3] & 0x20) != 0 {
                    dnssec_detected = true;
                }
            }
            _ => {}
        }
    }

    compute_result(name, "DoH", endpoint, latencies, count, dnssec_detected)
}

// probes a single dot upstream endpoint multiple times
async fn probe_dot(
    name: &str,
    endpoint: &str,
    query_bytes: &[u8],
    count: usize,
    timeout: Duration,
) -> BenchmarkResult {
    let mut latencies = Vec::new();
    let mut dnssec_detected = false;

    let client = match DotClient::from_preset(name, false) {
        Some(c) => c,
        None => {
            if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
                match DotClient::new(addr, name, false) {
                    Ok(c) => c,
                    Err(_) => {
                        return BenchmarkResult {
                            name: name.to_string(),
                            protocol: "DoT",
                            endpoint: endpoint.to_string(),
                            min_ms: 0.0,
                            avg_ms: 0.0,
                            max_ms: 0.0,
                            success_rate: 0.0,
                            dnssec: false,
                            responsive: false,
                        };
                    }
                }
            } else {
                return BenchmarkResult {
                    name: name.to_string(),
                    protocol: "DoT",
                    endpoint: endpoint.to_string(),
                    min_ms: 0.0,
                    avg_ms: 0.0,
                    max_ms: 0.0,
                    success_rate: 0.0,
                    dnssec: false,
                    responsive: false,
                };
            }
        }
    };

    for _ in 0..count {
        let start = Instant::now();
        match client.resolve(query_bytes, timeout).await {
            Ok(resp) => {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                latencies.push(ms);
                if resp.len() >= 4 && (resp[3] & 0x20) != 0 {
                    dnssec_detected = true;
                }
            }
            _ => {}
        }
    }

    compute_result(name, "DoT", endpoint, latencies, count, dnssec_detected)
}

fn compute_result(
    name: &str,
    protocol: &'static str,
    endpoint: &str,
    latencies: Vec<f64>,
    total_count: usize,
    dnssec: bool,
) -> BenchmarkResult {
    if latencies.is_empty() {
        return BenchmarkResult {
            name: name.to_string(),
            protocol,
            endpoint: endpoint.to_string(),
            min_ms: 0.0,
            avg_ms: 0.0,
            max_ms: 0.0,
            success_rate: 0.0,
            dnssec: false,
            responsive: false,
        };
    }

    let min_ms = latencies.iter().copied().fold(f64::INFINITY, f64::min);
    let max_ms = latencies.iter().copied().fold(0.0, f64::max);
    let avg_ms = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let success_rate = (latencies.len() as f64 / total_count as f64) * 100.0;

    BenchmarkResult {
        name: name.to_string(),
        protocol,
        endpoint: endpoint.to_string(),
        min_ms,
        avg_ms,
        max_ms,
        success_rate,
        dnssec,
        responsive: true,
    }
}

// executes full parallel benchmark across built-in presets and cached sources
pub async fn run_benchmark(
    cfg: &Config,
    opts: &BenchmarkOptions,
) -> Result<Vec<BenchmarkResult>, Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "Starting resolver benchmark for query '{}' (probes: {}, concurrency: {})...",
        opts.domain, opts.count, opts.concurrency
    );

    let query_wire = build_dns_query(&opts.domain, 1);
    let timeout = Duration::from_secs(opts.timeout_secs);
    let semaphore = Arc::new(Semaphore::new(opts.concurrency));

    let mut tasks = tokio::task::JoinSet::new();

    // 1. Queue DoH Presets
    let doh_presets = [
        ("cloudflare", "https://cloudflare-dns.com/dns-query"),
        ("quad9", "https://dns.quad9.net/dns-query"),
        ("mullvad", "https://dns.mullvad.net/dns-query"),
        (
            "mullvad-adblock",
            "https://adblock.dns.mullvad.net/dns-query",
        ),
        ("google", "https://dns.google/dns-query"),
        ("adguard-dns", "https://dns.adguard-dns.com/dns-query"),
    ];

    for (name, url) in doh_presets {
        if let Some(ref filter) = opts.protocol_filter {
            if filter.to_lowercase() != "all" && filter.to_lowercase() != "doh" {
                continue;
            }
        }
        let sem = semaphore.clone();
        let q = query_wire.clone();
        let name_str = name.to_string();
        let url_str = url.to_string();
        let count = opts.count;
        tasks.spawn(async move {
            let _permit = sem.acquire().await;
            probe_doh(&name_str, &url_str, &q, count, timeout).await
        });
    }

    // 2. Queue DoT Presets
    let dot_presets = [
        ("cloudflare", "1.1.1.1:853"),
        ("quad9", "9.9.9.9:853"),
        ("google", "8.8.8.8:853"),
        ("mullvad", "194.242.2.2:853"),
    ];

    for (name, ep) in dot_presets {
        if let Some(ref filter) = opts.protocol_filter {
            if filter.to_lowercase() != "all" && filter.to_lowercase() != "dot" {
                continue;
            }
        }
        let sem = semaphore.clone();
        let q = query_wire.clone();
        let name_str = name.to_string();
        let ep_str = ep.to_string();
        let count = opts.count;
        tasks.spawn(async move {
            let _permit = sem.acquire().await;
            probe_dot(&name_str, &ep_str, &q, count, timeout).await
        });
    }

    // 3. Queue Cached Remote Resolvers
    let cache_dir = SourceManager::default_cache_dir();
    let mgr = SourceManager::new();
    for src_cfg in cfg.sources.values() {
        if let Ok(entries) = mgr.fetch_or_load_cached(src_cfg, &cache_dir).await {
            for entry in entries.into_iter().take(20) {
                if let Some(stamp) = entry.primary_stamp {
                    match stamp.protocol {
                        StampProtocol::DoH => {
                            if let Some(ref filter) = opts.protocol_filter {
                                if filter.to_lowercase() != "all" && filter.to_lowercase() != "doh"
                                {
                                    continue;
                                }
                            }
                            let sem = semaphore.clone();
                            let q = query_wire.clone();
                            let name_str = entry.name.clone();
                            let url_str = stamp.doh_url.clone();
                            let count = opts.count;
                            tasks.spawn(async move {
                                let _permit = sem.acquire().await;
                                probe_doh(&name_str, &url_str, &q, count, timeout).await
                            });
                        }
                        StampProtocol::DoT => {
                            if let Some(ref filter) = opts.protocol_filter {
                                if filter.to_lowercase() != "all" && filter.to_lowercase() != "dot"
                                {
                                    continue;
                                }
                            }
                            if let Some(sa) = stamp.server_addr {
                                let sem = semaphore.clone();
                                let q = query_wire.clone();
                                let name_str = entry.name.clone();
                                let ep_str = sa.to_string();
                                let count = opts.count;
                                tasks.spawn(async move {
                                    let _permit = sem.acquire().await;
                                    probe_dot(&name_str, &ep_str, &q, count, timeout).await
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let mut results = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(benchmark_res) = res {
            results.push(benchmark_res);
        }
    }

    // Sort results: responsive servers first, then sorted by avg latency ascending
    results.sort_by(|a, b| match (a.responsive, b.responsive) {
        (true, true) => a
            .avg_ms
            .partial_cmp(&b.avg_ms)
            .unwrap_or(std::cmp::Ordering::Equal),
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (false, false) => a.name.cmp(&b.name),
    });

    display_results(&results, opts.top);

    Ok(results)
}

// prints formatted ascii benchmark comparison table
pub fn display_results(results: &[BenchmarkResult], top_n: usize) {
    println!(
        "\n{:<4} {:<24} {:<8} {:<12} {:<14} {:<10} DNSSEC",
        "RANK", "RESOLVER NAME", "PROTO", "AVG (MS)", "MIN / MAX (MS)", "SUCCESS"
    );
    println!("{}", "-".repeat(82));

    let display_items = results.iter().take(top_n);
    let mut rank = 1;
    let mut fastest = None;

    for r in display_items {
        if r.responsive {
            if fastest.is_none() {
                fastest = Some(r.clone());
            }
            let min_max = format!("{:.1} / {:.1}", r.min_ms, r.max_ms);
            let success = format!("{:.0}%", r.success_rate);
            let dnssec_str = if r.dnssec { "Yes" } else { "No" };
            println!(
                "{:<4} {:<24} {:<8} {:<12.1} {:<14} {:<10} {}",
                rank, r.name, r.protocol, r.avg_ms, min_max, success, dnssec_str
            );
        } else {
            println!(
                "{:<4} {:<24} {:<8} {:<12} {:<14} {:<10} -",
                rank, r.name, r.protocol, "TIMEOUT", "-", "0%"
            );
        }
        rank += 1;
    }

    println!("{}", "-".repeat(82));
    let responsive_count = results.iter().filter(|r| r.responsive).count();
    println!(
        "Benchmark completed: {} tested, {} responsive.",
        results.len(),
        responsive_count
    );

    if let Some(best) = fastest {
        println!(
            "Fastest recommended: {} ({}) with {:.1} ms average latency.\n",
            best.name, best.protocol, best.avg_ms
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_result_calculation() {
        let latencies = vec![20.0, 30.0, 40.0];
        let res = compute_result(
            "test-resolver",
            "DoH",
            "https://test.invalid",
            latencies,
            3,
            true,
        );
        assert!(res.responsive);
        assert_eq!(res.min_ms, 20.0);
        assert_eq!(res.max_ms, 40.0);
        assert_eq!(res.avg_ms, 30.0);
        assert_eq!(res.success_rate, 100.0);
        assert!(res.dnssec);
    }

    #[test]
    fn test_compute_result_all_timeouts() {
        let res = compute_result(
            "unreachable",
            "DoH",
            "https://unreachable.invalid",
            vec![],
            3,
            false,
        );
        assert!(!res.responsive);
        assert_eq!(res.success_rate, 0.0);
    }
}
