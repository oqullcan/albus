//! zero-allocation domain allowlist and exception engine.
//!
//! allows specific enterprise, banking, or gaming domains to bypass ad/tracker/malware blocklists,
//! supporting both exact domain matches ("auth.bank.com") and wildcard suffixes ("*.teams.microsoft.com").

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct DomainAllowlist {
    exact: HashSet<String>,
    wildcards: Vec<String>,
}

impl DomainAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    // normalizes a domain pattern removing leading/trailing dots and asterisks
    fn normalize(domain: &str) -> String {
        domain
            .trim()
            .to_ascii_lowercase()
            .trim_matches('.')
            .to_string()
    }

    pub fn add(&mut self, pattern: &str) {
        let trimmed = pattern.trim().to_ascii_lowercase();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return;
        }

        if let Some(rest) = trimmed.strip_prefix("*.") {
            let normalized = Self::normalize(rest);
            if !normalized.is_empty() && !self.wildcards.contains(&normalized) {
                self.wildcards.push(normalized);
            }
        } else if let Some(rest) = trimmed.strip_prefix('.') {
            let normalized = Self::normalize(rest);
            if !normalized.is_empty() && !self.wildcards.contains(&normalized) {
                self.wildcards.push(normalized);
            }
        } else if let Some(rest) = trimmed.strip_prefix('=') {
            // explicit exact match
            let normalized = Self::normalize(rest);
            if !normalized.is_empty() {
                self.exact.insert(normalized);
            }
        } else {
            let normalized = Self::normalize(&trimmed);
            if !normalized.is_empty() {
                self.exact.insert(normalized);
            }
        }
    }

    pub fn from_iter<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowlist = Self::new();
        for item in iter {
            allowlist.add(item.as_ref());
        }
        allowlist
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut allowlist = Self::new();
        const MAX_ALLOWLIST_ENTRIES: usize = 100_000;

        for line in reader.lines() {
            let line = line?;
            if allowlist.len() >= MAX_ALLOWLIST_ENTRIES {
                break;
            }
            allowlist.add(&line);
        }

        Ok(allowlist)
    }

    // checks if a domain or any of its parent zones are explicitly whitelisted
    pub fn is_allowed(&self, domain: &str) -> bool {
        if self.exact.is_empty() && self.wildcards.is_empty() {
            return false;
        }

        let normalized = Self::normalize(domain);
        if self.exact.contains(&normalized) {
            return true;
        }

        for suffix in &self.wildcards {
            if normalized == *suffix || normalized.ends_with(&format!(".{}", suffix)) {
                return true;
            }
        }

        false
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcards.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_allowlist_match() {
        let mut al = DomainAllowlist::new();
        al.add("auth.bank.com");
        al.add("=portal.university.edu");

        assert!(al.is_allowed("auth.bank.com"));
        assert!(al.is_allowed("AUTH.BANK.COM."));
        assert!(al.is_allowed("portal.university.edu"));
        assert!(!al.is_allowed("sub.auth.bank.com"));
        assert!(!al.is_allowed("evil.com"));
    }

    #[test]
    fn test_wildcard_allowlist_match() {
        let mut al = DomainAllowlist::new();
        al.add("*.microsoft.com");
        al.add(".google.internal");

        assert!(al.is_allowed("microsoft.com"));
        assert!(al.is_allowed("teams.microsoft.com"));
        assert!(al.is_allowed("sub.teams.microsoft.com."));
        assert!(al.is_allowed("cloud.google.internal"));
        assert!(!al.is_allowed("fakemicrosoft.com"));
    }
}
