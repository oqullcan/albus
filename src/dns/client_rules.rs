//! per-client and ip/cidr-differentiated filtering rules engine.
//!
//! permits configuring distinct filtering profiles, blocklists, allowlists, and
//! ipv6 policies based on the incoming dns client source ip or cidr subnet.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

use crate::dns::ip_filter::IpRule;
use crate::dns::pattern::PatternMatcher;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientDecision {
    Allowed(&'static str),
    Blocked(&'static str),
    DropIPv6,
    PassThrough,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProfileConfig {
    pub name: String,
    pub client_ips: Vec<String>,
    #[serde(default)]
    pub block_all: bool,
    #[serde(default)]
    pub bypass_blocklist: bool,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub block_ipv6: Option<bool>,
}

#[derive(Clone)]
pub struct ClientProfile {
    pub name: String,
    pub ip_rules: Vec<IpRule>,
    pub block_all: bool,
    pub bypass_blocklist: bool,
    pub blocked_domains_matcher: Arc<PatternMatcher>,
    pub allowed_domains_matcher: Arc<PatternMatcher>,
    pub block_ipv6: Option<bool>,
}

impl ClientProfile {
    pub fn from_config(cfg: &ClientProfileConfig) -> Self {
        let mut ip_rules = Vec::new();
        for s in &cfg.client_ips {
            if let Some(rule) = IpRule::parse(s) {
                ip_rules.push(rule);
            }
        }

        let mut blocked_matcher = PatternMatcher::new();
        for d in &cfg.blocked_domains {
            blocked_matcher.add_rule(d);
        }

        let mut allowed_matcher = PatternMatcher::new();
        for d in &cfg.allowed_domains {
            allowed_matcher.add_rule(d);
        }

        Self {
            name: cfg.name.clone(),
            ip_rules,
            block_all: cfg.block_all,
            bypass_blocklist: cfg.bypass_blocklist,
            blocked_domains_matcher: Arc::new(blocked_matcher),
            allowed_domains_matcher: Arc::new(allowed_matcher),
            block_ipv6: cfg.block_ipv6,
        }
    }

    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        self.ip_rules.iter().any(|r| r.matches(ip))
    }
}

#[derive(Clone, Default)]
pub struct ClientRuleEngine {
    profiles: Vec<ClientProfile>,
}

impl ClientRuleEngine {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }

    pub fn from_configs(configs: &[ClientProfileConfig]) -> Self {
        let profiles = configs.iter().map(ClientProfile::from_config).collect();
        Self { profiles }
    }

    pub fn add_profile(&mut self, profile: ClientProfile) {
        self.profiles.push(profile);
    }

    // evaluates client source ip and target domain name returning filtering decision
    pub fn evaluate(&self, client_ip: IpAddr, domain: &str, qtype: u16) -> ClientDecision {
        for profile in &self.profiles {
            if profile.matches_ip(client_ip) {
                if profile.block_all {
                    return ClientDecision::Blocked("client-profile-block-all");
                }

                if qtype == 28 && profile.block_ipv6 == Some(true) {
                    return ClientDecision::DropIPv6;
                }

                if profile.allowed_domains_matcher.matches(domain) {
                    return ClientDecision::Allowed("client-profile-allowlist");
                }

                if profile.blocked_domains_matcher.matches(domain) {
                    return ClientDecision::Blocked("client-profile-blocklist");
                }

                if profile.bypass_blocklist {
                    return ClientDecision::Allowed("client-profile-bypass");
                }
            }
        }

        ClientDecision::PassThrough
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_rule_engine_matching_and_decisions() {
        let profiles_cfg = vec![
            ClientProfileConfig {
                name: "kids-tablet".to_string(),
                client_ips: vec!["192.168.1.105".to_string()],
                block_all: false,
                bypass_blocklist: false,
                blocked_domains: vec!["tiktok.com".to_string(), "*gambling*".to_string()],
                allowed_domains: vec!["wikipedia.org".to_string()],
                block_ipv6: Some(true),
            },
            ClientProfileConfig {
                name: "dev-workstation".to_string(),
                client_ips: vec!["10.0.0.0/8".to_string()],
                block_all: false,
                bypass_blocklist: true,
                blocked_domains: vec![],
                allowed_domains: vec![],
                block_ipv6: None,
            },
        ];

        let engine = ClientRuleEngine::from_configs(&profiles_cfg);

        // Kids tablet IP checks
        let tablet_ip: IpAddr = "192.168.1.105".parse().unwrap();
        assert_eq!(
            engine.evaluate(tablet_ip, "tiktok.com", 1),
            ClientDecision::Blocked("client-profile-blocklist")
        );
        assert_eq!(
            engine.evaluate(tablet_ip, "online-gambling-site.com", 1),
            ClientDecision::Blocked("client-profile-blocklist")
        );
        assert_eq!(
            engine.evaluate(tablet_ip, "wikipedia.org", 1),
            ClientDecision::Allowed("client-profile-allowlist")
        );
        assert_eq!(
            engine.evaluate(tablet_ip, "google.com", 28), // AAAA query
            ClientDecision::DropIPv6
        );

        // Dev workstation in 10.0.0.0/8 bypasses global blocklist
        let dev_ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(
            engine.evaluate(dev_ip, "ad-server.com", 1),
            ClientDecision::Allowed("client-profile-bypass")
        );

        // Unconfigured client passes through
        let guest_ip: IpAddr = "192.168.1.250".parse().unwrap();
        assert_eq!(
            engine.evaluate(guest_ip, "ad-server.com", 1),
            ClientDecision::PassThrough
        );
    }
}
