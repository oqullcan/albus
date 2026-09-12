//! advanced domain pattern matching supporting exact (=), substring (*), prefix, and suffix/wildcard rules.
//!
//! implements pattern matching rules compatible with dnscrypt-proxy blocklists and allowlists.

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternRule {
    Exact(String),     // =example.com (matches only example.com, not sub.example.com)
    Substring(String), // *ads* (matches if domain contains substring 'ads')
    Prefix(String),    // ads.* (matches if domain starts with 'ads.')
    Suffix(String),    // *.example.com or example.com (matches example.com and all subdomains)
}

impl PatternRule {
    pub fn to_rule_string(&self) -> String {
        match self {
            PatternRule::Exact(d) => format!("={}", d),
            PatternRule::Substring(s) => format!("*{}*", s),
            PatternRule::Prefix(p) => format!("{}*", p),
            PatternRule::Suffix(s) => format!("*.{}", s),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PatternMatcher {
    exact: HashSet<String>,
    substrings: Vec<String>,
    prefixes: Vec<String>,
    suffixes: HashSet<String>,
}

impl PatternMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_rules<I: IntoIterator<Item = PatternRule>>(rules: I) -> Self {
        let mut matcher = Self::new();
        for r in rules {
            matcher.add(r);
        }
        matcher
    }

    pub fn from_text(content: &str) -> Self {
        let mut matcher = Self::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rule) = Self::parse_rule(trimmed) {
                matcher.add(rule);
            }
        }
        matcher
    }

    pub fn parse_rule(raw: &str) -> Option<PatternRule> {
        let clean = raw.trim().to_ascii_lowercase();
        if clean.is_empty() || clean.starts_with('#') || clean.starts_with(';') {
            return None;
        }

        // Exact match rule (=domain.com)
        if let Some(exact) = clean.strip_prefix('=') {
            let e = exact.trim_end_matches('.');
            if !e.is_empty() {
                return Some(PatternRule::Exact(e.to_string()));
            }
            return None;
        }

        // Substring match rule (*keyword*)
        if clean.starts_with('*') && clean.ends_with('*') && clean.len() > 2 {
            let sub = &clean[1..clean.len() - 1];
            if !sub.contains('*') && !sub.is_empty() {
                return Some(PatternRule::Substring(sub.to_string()));
            }
        }

        // Prefix match rule (prefix.*)
        if clean.ends_with(".*") && clean.len() > 2 {
            let pref = &clean[..clean.len() - 2];
            if !pref.is_empty() {
                return Some(PatternRule::Prefix(format!("{}.", pref)));
            }
        }

        // Suffix/wildcard rule (*.domain.com)
        if let Some(suff) = clean.strip_prefix("*.") {
            let s = suff.trim_end_matches('.');
            if !s.is_empty() {
                return Some(PatternRule::Suffix(s.to_string()));
            }
        }

        // Standard domain or suffix
        let s = clean.trim_start_matches('.').trim_end_matches('.');
        if !s.is_empty() {
            Some(PatternRule::Suffix(s.to_string()))
        } else {
            None
        }
    }

    pub fn add_rule(&mut self, raw: &str) {
        if let Some(rule) = Self::parse_rule(raw) {
            self.add(rule);
        }
    }

    pub fn add(&mut self, rule: PatternRule) {
        match rule {
            PatternRule::Exact(d) => {
                self.exact.insert(d);
            }
            PatternRule::Substring(s) => {
                if !self.substrings.contains(&s) {
                    self.substrings.push(s);
                }
            }
            PatternRule::Prefix(p) => {
                if !self.prefixes.contains(&p) {
                    self.prefixes.push(p);
                }
            }
            PatternRule::Suffix(s) => {
                self.suffixes.insert(s);
            }
        }
    }

    pub fn all_rules(&self) -> Vec<PatternRule> {
        let mut rules = Vec::with_capacity(self.len());
        for e in &self.exact {
            rules.push(PatternRule::Exact(e.clone()));
        }
        for s in &self.substrings {
            rules.push(PatternRule::Substring(s.clone()));
        }
        for p in &self.prefixes {
            rules.push(PatternRule::Prefix(p.clone()));
        }
        for s in &self.suffixes {
            rules.push(PatternRule::Suffix(s.clone()));
        }
        rules
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.substrings.is_empty()
            && self.prefixes.is_empty()
            && self.suffixes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.substrings.len() + self.prefixes.len() + self.suffixes.len()
    }

    pub fn matches(&self, domain: &str) -> bool {
        let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return false;
        }

        // 1. Exact match check
        if self.exact.contains(&clean) {
            return true;
        }

        // 2. Substring match check
        for sub in &self.substrings {
            if clean.contains(sub) {
                return true;
            }
        }

        // 3. Prefix match check
        for pref in &self.prefixes {
            if clean.starts_with(pref) {
                return true;
            }
        }

        // 4. Suffix/subdomain match check (O(labels) lookup with 0 heap allocations)
        if self.suffixes.contains(&clean) {
            return true;
        }
        let mut remainder = clean.as_str();
        while let Some(dot_idx) = remainder.find('.') {
            remainder = &remainder[dot_idx + 1..];
            if self.suffixes.contains(remainder) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching_rules() {
        let rules = r#"
        # exact match
        =exact.example.com
        
        # substring match
        *telemetry*
        
        # prefix match
        ads.*
        
        # suffix match
        *.doubleclick.net
        analytics.google.com
        "#;

        let matcher = PatternMatcher::from_text(rules);

        // Exact match
        assert!(matcher.matches("exact.example.com"));
        assert!(!matcher.matches("sub.exact.example.com")); // exact rule must not match subdomains

        // Substring match
        assert!(matcher.matches("client-telemetry.corp.internal"));
        assert!(matcher.matches("telemetry.microsoft.com"));
        assert!(!matcher.matches("regular-site.com"));

        // Prefix match
        assert!(matcher.matches("ads.example.com"));
        assert!(matcher.matches("ads.tracker.org"));
        assert!(!matcher.matches("myads.example.com"));

        // Suffix match
        assert!(matcher.matches("doubleclick.net"));
        assert!(matcher.matches("ad.doubleclick.net"));
        assert!(matcher.matches("sub.ad.doubleclick.net"));
        assert!(matcher.matches("analytics.google.com"));
        assert!(matcher.matches("sub.analytics.google.com"));
        assert!(!matcher.matches("google.com"));
    }
}
