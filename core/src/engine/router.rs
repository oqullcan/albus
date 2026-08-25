// privacy-oriented domain and ip routing evaluator with custom passthrough whitelist

use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteAction {
    BypassDpi,
    Direct,
}

pub struct DomainRouter {
    whitelist: Vec<String>,
}

impl DomainRouter {
    pub fn new() -> Self {
        // default latency-critical and domestic banking services
        let default_list = vec![
            "isbank.com.tr".to_string(),
            "garantibbva.com.tr".to_string(),
            "ziraatbank.com.tr".to_string(),
            "akbank.com".to_string(),
            "yapikredi.com.tr".to_string(),
            "turkiye.gov.tr".to_string(),
            "gib.gov.tr".to_string(),
            "riotgames.com".to_string(),
            "val.pvp.net".to_string(),
            "steampowered.com".to_string(),
        ];
        Self { whitelist: default_list }
    }

    pub fn with_custom_rules(mut self, rules: &[String]) -> Self {
        for r in rules {
            let trimmed = r.trim().to_lowercase();
            if !trimmed.is_empty() {
                self.whitelist.push(trimmed);
            }
        }
        self
    }

    // determines whether traffic should undergo dpi evasion or direct native passthrough
    pub fn evaluate(&self, target_ip: Option<IpAddr>, target_domain: Option<&str>) -> RouteAction {
        // 1. check private / local network ips (always direct)
        if let Some(ip) = target_ip {
            if Self::is_private_ip(ip) {
                return RouteAction::Direct;
            }
        }

        // 2. check domain whitelist
        if let Some(domain) = target_domain {
            let d_lower = domain.to_lowercase();
            if d_lower.ends_with(".local")
                || d_lower.ends_with(".internal")
                || d_lower.ends_with(".lan")
                || d_lower == "localhost"
            {
                return RouteAction::Direct;
            }

            for rule in &self.whitelist {
                let clean_rule = rule.trim_start_matches("*.").to_lowercase();
                if d_lower == clean_rule || d_lower.ends_with(&format!(".{}", clean_rule)) {
                    return RouteAction::Direct;
                }
            }
        }

        // 3. standard internet traffic undergoes dpi evasion
        RouteAction::BypassDpi
    }

    fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || octets[0] == 0
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 10)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_private_ip_routing() {
        let router = DomainRouter::new();
        let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let public_ip = IpAddr::V4(Ipv4Addr::new(104, 21, 5, 12));

        assert_eq!(router.evaluate(Some(loopback), None), RouteAction::Direct);
        assert_eq!(router.evaluate(Some(lan_ip), None), RouteAction::Direct);
        assert_eq!(router.evaluate(Some(public_ip), None), RouteAction::BypassDpi);
    }

    #[test]
    fn test_whitelist_domain_routing() {
        let router = DomainRouter::new().with_custom_rules(&["bank.com".to_string(), "*.internal.corp".to_string()]);

        assert_eq!(router.evaluate(None, Some("bank.com")), RouteAction::Direct);
        assert_eq!(router.evaluate(None, Some("sub.bank.com")), RouteAction::Direct);
        assert_eq!(router.evaluate(None, Some("service.internal.corp")), RouteAction::Direct);
        assert_eq!(router.evaluate(None, Some("myrouter.local")), RouteAction::Direct);
        assert_eq!(router.evaluate(None, Some("blocked-news.com")), RouteAction::BypassDpi);
    }
}

