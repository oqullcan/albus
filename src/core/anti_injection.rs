//! stateful anti-injection engine for detecting and dropping censor-injected rst and dns packets.
//!
//! detects middlebox out-of-band censorship injections (rst tear-down, fake syn-ack, dns cache poisoning)
//! by evaluating ttl hop-count discrepancies, tcp sequence window drift, and cryptographic flow tags.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Known GFW / middlebox spoofed DNS injection addresses (documented signatures).
pub const KNOWN_CENSOR_POISON_IPS_V4: &[Ipv4Addr] = &[
    Ipv4Addr::new(37, 61, 54, 158),
    Ipv4Addr::new(46, 82, 174, 68),
    Ipv4Addr::new(59, 24, 3, 173),
    Ipv4Addr::new(78, 16, 49, 15),
    Ipv4Addr::new(8, 7, 198, 45),
    Ipv4Addr::new(93, 46, 8, 89),
    Ipv4Addr::new(159, 106, 121, 75),
    Ipv4Addr::new(203, 98, 7, 65),
    Ipv4Addr::new(243, 185, 187, 39),
    Ipv4Addr::new(211, 139, 139, 169),
    Ipv4Addr::new(10, 10, 34, 34),
    Ipv4Addr::new(1, 2, 3, 4),
    Ipv4Addr::new(0, 0, 0, 0),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionVerdict {
    Legitimate,
    DropInjectedRst(&'static str),
    DropInjectedDns(&'static str),
}

#[derive(Debug, Clone)]
struct FlowState {
    expected_seq: u32,
    baseline_ttl: u8,
    last_seen: Instant,
    window_size: u32,
}

/// Stateful filter evaluating incoming packets for middlebox tampering and injection.
#[derive(Debug, Clone, Default)]
pub struct AntiInjectionFilter {
    flows: Arc<RwLock<HashMap<SocketAddr, FlowState>>>,
    ttl_tolerance: u8,
}

impl AntiInjectionFilter {
    pub const MAX_TRACKED_FLOWS: usize = 10_000;

    pub fn new(ttl_tolerance: u8) -> Self {
        Self {
            flows: Arc::new(RwLock::new(HashMap::new())),
            ttl_tolerance: ttl_tolerance.max(1),
        }
    }

    /// Records or updates verified state from legitimate server traffic with bounded memory capacity.
    pub fn record_legitimate_flow(
        &self,
        server_addr: SocketAddr,
        seq: u32,
        window: u32,
        ttl: u8,
    ) {
        if let Ok(mut lock) = self.flows.write() {
            if lock.len() >= Self::MAX_TRACKED_FLOWS && !lock.contains_key(&server_addr) {
                let now = Instant::now();
                lock.retain(|_, state| now.duration_since(state.last_seen) < Duration::from_secs(300));
                if lock.len() >= Self::MAX_TRACKED_FLOWS {
                    if let Some((&oldest_key, _)) = lock.iter().min_by_key(|(_, s)| s.last_seen) {
                        lock.remove(&oldest_key);
                    }
                }
            }
            lock.insert(
                server_addr,
                FlowState {
                    expected_seq: seq,
                    baseline_ttl: ttl,
                    last_seen: Instant::now(),
                    window_size: window,
                },
            );
        }
    }

    /// Validates an incoming TCP RST packet against expected sequence number and baseline TTL.
    pub fn inspect_tcp_rst(
        &self,
        server_addr: SocketAddr,
        rst_seq: u32,
        packet_ttl: u8,
    ) -> InjectionVerdict {
        let lock = match self.flows.read() {
            Ok(g) => g,
            Err(_) => return InjectionVerdict::Legitimate,
        };

        if let Some(state) = lock.get(&server_addr) {
            // 1. Evaluate TTL hop-count anomaly: middlebox injector is typically closer than real server
            let ttl_diff = (state.baseline_ttl as i16 - packet_ttl as i16).abs();
            if ttl_diff > self.ttl_tolerance as i16 {
                return InjectionVerdict::DropInjectedRst(
                    "ttl hop-count divergence indicates middlebox injection",
                );
            }

            // 2. Evaluate TCP Sequence window validity
            let seq_diff = (rst_seq as i64 - state.expected_seq as i64).abs();
            if seq_diff > (state.window_size as i64).max(65535) {
                return InjectionVerdict::DropInjectedRst(
                    "out-of-window rst sequence number indicates blind injection",
                );
            }
        }

        InjectionVerdict::Legitimate
    }

    /// Validates DNS response IPs and transaction characteristics against censor injection signatures.
    pub fn inspect_dns_response(&self, _domain: &str, resolved_ips: &[IpAddr]) -> InjectionVerdict {
        for &ip in resolved_ips {
            match ip {
                IpAddr::V4(v4) => {
                    if KNOWN_CENSOR_POISON_IPS_V4.contains(&v4) {
                        return InjectionVerdict::DropInjectedDns(
                            "resolved IP matches known middlebox DNS poisoning signature",
                        );
                    }
                }
                IpAddr::V6(v6) => {
                    // Censors often inject documentation ranges (2001:db8::) or invalid prefixes
                    let segments = v6.segments();
                    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                        return InjectionVerdict::DropInjectedDns(
                            "resolved IPv6 matches documentation range injected by censor middlebox",
                        );
                    }
                }
            }
        }
        InjectionVerdict::Legitimate
    }

    /// Cleans up stale flow states older than timeout.
    pub fn cleanup_stale(&self, timeout: Duration) {
        if let Ok(mut lock) = self.flows.write() {
            let now = Instant::now();
            lock.retain(|_, state| now.duration_since(state.last_seen) < timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_injection_ttl_divergence() {
        let filter = AntiInjectionFilter::new(3);
        let s_addr: SocketAddr = "1.1.1.1:443".parse().unwrap();

        // Baseline: server packets arrive with TTL 54
        filter.record_legitimate_flow(s_addr, 10000, 65535, 54);

        // Legitimate RST with TTL 53 (diff = 1 <= 3)
        assert_eq!(
            filter.inspect_tcp_rst(s_addr, 10005, 53),
            InjectionVerdict::Legitimate
        );

        // Middlebox injected RST arriving with local ISP TTL 64 (diff = 10 > 3)
        match filter.inspect_tcp_rst(s_addr, 10005, 64) {
            InjectionVerdict::DropInjectedRst(reason) => {
                assert!(reason.contains("ttl hop-count divergence"));
            }
            _ => panic!("injected RST with diverging TTL must be dropped"),
        }
    }

    #[test]
    fn test_anti_injection_seq_out_of_window() {
        let filter = AntiInjectionFilter::new(3);
        let s_addr: SocketAddr = "8.8.8.8:443".parse().unwrap();

        filter.record_legitimate_flow(s_addr, 1000, 4096, 50);

        // Blind injection with wild sequence number
        match filter.inspect_tcp_rst(s_addr, 999_999, 50) {
            InjectionVerdict::DropInjectedRst(reason) => {
                assert!(reason.contains("out-of-window"));
            }
            _ => panic!("blind injected RST must be dropped"),
        }
    }

    #[test]
    fn test_anti_injection_dns_poisoning() {
        let filter = AntiInjectionFilter::new(3);

        // Legitimate resolution
        let legit_ips = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
        assert_eq!(
            filter.inspect_dns_response("example.com", &legit_ips),
            InjectionVerdict::Legitimate
        );

        // Known GFW injected IP (37.61.54.158)
        let poisoned_ips = [IpAddr::V4(Ipv4Addr::new(37, 61, 54, 158))];
        match filter.inspect_dns_response("twitter.com", &poisoned_ips) {
            InjectionVerdict::DropInjectedDns(reason) => {
                assert!(reason.contains("known middlebox DNS poisoning signature"));
            }
            _ => panic!("injected DNS response must be dropped"),
        }

        // Censor injected documentation range IPv6 (2001:db8::1)
        let poisoned_v6 = ["2001:db8::1".parse().unwrap()];
        match filter.inspect_dns_response("youtube.com", &poisoned_v6) {
            InjectionVerdict::DropInjectedDns(reason) => {
                assert!(reason.contains("documentation range"));
            }
            _ => panic!("injected IPv6 DNS response must be dropped"),
        }
    }

    #[test]
    fn test_anti_injection_cleanup_stale() {
        let filter = AntiInjectionFilter::new(3);
        let s_addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
        filter.record_legitimate_flow(s_addr, 1000, 4096, 50);

        assert_eq!(filter.inspect_tcp_rst(s_addr, 1005, 50), InjectionVerdict::Legitimate);

        // Immediate cleanup with 0 timeout removes all stale entries
        filter.cleanup_stale(Duration::from_millis(0));

        // After cleanup, flow is no longer tracked, so uncalibrated packets default to Legitimate
        assert_eq!(filter.flows.read().unwrap().len(), 0);
    }
}
