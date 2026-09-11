//! automated blocklist downloader, normalizer, and merger tool (generate-domains-blocklist).
//!
//! fetches domain blocklists from public feeds (adaway, stevenblack, easylist, disconnect),
//! parses multiple formats (adblock plus, hosts file, dnsmasq, plain domain lists),
//! excludes allowed domains, appends time schedules, and compiles an optimized blocked-names.txt.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

pub const DEFAULT_FEED_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
];

/// Parses text content in various formats (hosts, adblock plus, dnsmasq, plain) and extracts domain names.
pub fn parse_domain_list(content: &str) -> HashSet<String> {
    let mut domains = HashSet::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') || trimmed.starts_with(';') {
            continue;
        }

        // Strip inline comments
        let line_clean = match trimmed.split_once('#') {
            Some((clean, _)) => clean.trim(),
            None => trimmed,
        };

        // Format 1: AdBlock Plus / uBlock: ||example.com^ or ||example.com^$third-party
        if let Some(rest) = line_clean.strip_prefix("||") {
            let mut domain = rest;
            if let Some((d, _)) = domain.split_once('^') {
                domain = d;
            }
            if let Some((d, _)) = domain.split_once('$') {
                domain = d;
            }
            let clean_d = clean_domain_name(domain);
            if is_valid_domain(&clean_d) {
                domains.insert(clean_d);
            }
            continue;
        }

        // Format 2: Dnsmasq: address=/example.com/ or address=/example.com/0.0.0.0
        if let Some(rest) = line_clean.strip_prefix("address=/") {
            if let Some((d, _)) = rest.split_once('/') {
                let clean_d = clean_domain_name(d);
                if is_valid_domain(&clean_d) {
                    domains.insert(clean_d);
                }
            }
            continue;
        }

        // Format 3: Hosts file: 0.0.0.0 example.com or 127.0.0.1 example.com
        let parts: Vec<&str> = line_clean.split_whitespace().collect();
        if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::1" || parts[0] == "::") {
            for &host in &parts[1..] {
                let clean_d = clean_domain_name(host);
                if is_valid_domain(&clean_d) && clean_d != "localhost" && clean_d != "local" && !clean_d.ends_with(".localdomain") {
                    domains.insert(clean_d);
                }
            }
            continue;
        }

        // Format 4: Plain domain or wildcard: example.com, *.example.com, =example.com
        if parts.len() == 1 {
            let clean_d = clean_domain_name(parts[0]);
            if is_valid_domain(&clean_d) {
                domains.insert(clean_d);
            }
        }
    }

    domains
}

/// Parses an allowlist file (domains that should never be blocked).
pub fn parse_allowlist<P: AsRef<Path>>(path: P) -> HashSet<String> {
    let mut allow = HashSet::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let clean = clean_domain_name(trimmed);
            if is_valid_domain(&clean) {
                allow.insert(clean);
            }
        }
    }
    allow
}

/// Parses time-restricted rules mapping domains to schedule tags (e.g. `example.com @work`).
pub fn parse_time_restrictions<P: AsRef<Path>>(path: P) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && parts[1].starts_with('@') {
                let clean = clean_domain_name(parts[0]);
                map.insert(clean, parts[1].to_string());
            }
        }
    }
    map
}

/// Helper to sanitize a domain string.
fn clean_domain_name(s: &str) -> String {
    s.trim()
        .trim_start_matches("=.")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Basic sanity check to ensure a domain candidate contains valid characters and has a dot.
fn is_valid_domain(d: &str) -> bool {
    let clean = d.trim_start_matches('*').trim_start_matches('.').trim_start_matches('=');
    if clean.is_empty() || clean.len() > 253 {
        return false;
    }
    // Must contain a dot (or be a recognized wildcard)
    if !clean.contains('.') {
        return false;
    }
    // Must not contain spaces, slashes, or invalid URI characters
    !clean.contains(' ') && !clean.contains('/') && !clean.contains(':') && !clean.contains('?')
}

/// Downloads and compiles blocklists into a normalized output file.
pub async fn compile_blocklist(
    sources: &[String],
    allowlist_path: Option<&str>,
    time_restricted_path: Option<&str>,
    local_additions_path: Option<&str>,
    output_path: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let mut all_domains = HashSet::new();

    // 1. Process feed sources
    for src in sources {
        let src_trimmed = src.trim();
        if src_trimmed.is_empty() || src_trimmed.starts_with('#') {
            continue;
        }

        if let Some(file_path) = src_trimmed.strip_prefix("file:") {
            match fs::read_to_string(file_path) {
                Ok(content) => {
                    let parsed = parse_domain_list(&content);
                    info!(source = file_path, count = parsed.len(), "Loaded local blocklist file");
                    all_domains.extend(parsed);
                }
                Err(e) => warn!("Failed to read local blocklist file {}: {}", file_path, e),
            }
        } else if src_trimmed.starts_with("http://") || src_trimmed.starts_with("https://") {
            info!(url = src_trimmed, "Downloading blocklist feed...");
            match client.get(src_trimmed).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.text().await {
                        Ok(body) => {
                            let parsed = parse_domain_list(&body);
                            info!(url = src_trimmed, count = parsed.len(), "Downloaded and parsed blocklist feed");
                            all_domains.extend(parsed);
                        }
                        Err(e) => warn!("Failed to read response body from {}: {}", src_trimmed, e),
                    }
                }
                Ok(resp) => warn!("Feed {} returned HTTP status {}", src_trimmed, resp.status()),
                Err(e) => warn!("Failed to download feed {}: {}", src_trimmed, e),
            }
        }
    }

    // 2. Load local additions if specified
    if let Some(path) = local_additions_path {
        if Path::new(path).exists() {
            if let Ok(content) = fs::read_to_string(path) {
                let parsed = parse_domain_list(&content);
                info!(path = path, count = parsed.len(), "Appended local additions");
                all_domains.extend(parsed);
            }
        }
    }

    // 3. Filter out allowlisted domains
    if let Some(path) = allowlist_path {
        if Path::new(path).exists() {
            let allow = parse_allowlist(path);
            let before = all_domains.len();
            all_domains.retain(|d| !allow.contains(d));
            info!(path = path, removed = before - all_domains.len(), "Filtered allowlisted domains");
        }
    }

    // 4. Load time restrictions
    let time_restrictions = if let Some(path) = time_restricted_path {
        if Path::new(path).exists() {
            parse_time_restrictions(path)
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    // 5. Sort domains for deterministic output
    let mut sorted_domains: Vec<String> = all_domains.into_iter().collect();
    sorted_domains.sort_unstable();

    // 6. Write output file
    let mut out_content = String::new();
    out_content.push_str("# Albus compiled domain blocklist\n");
    out_content.push_str(&format!("# Total active blocked domains: {}\n\n", sorted_domains.len()));

    for domain in &sorted_domains {
        if let Some(schedule) = time_restrictions.get(domain) {
            out_content.push_str(&format!("{}\t{}\n", domain, schedule));
        } else {
            out_content.push_str(&format!("{}\n", domain));
        }
    }

    fs::write(output_path, out_content)?;
    info!(output = output_path, total = sorted_domains.len(), "Compiled domain blocklist saved successfully");

    Ok(sorted_domains.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_list_formats() {
        let sample = r#"
        # AdBlock Plus rule
        ||adserver.com^$third-party
        ||tracking.net^

        # Dnsmasq rule
        address=/badsite.org/0.0.0.0
        address=/malware.biz/

        # Hosts file rule
        0.0.0.0 telemetry.io stats.telemetry.io
        127.0.0.1 spy.net

        # Plain domain
        analytics.com
        *.wildcard-tracker.com
        "#;

        let parsed = parse_domain_list(sample);
        assert!(parsed.contains("adserver.com"));
        assert!(parsed.contains("tracking.net"));
        assert!(parsed.contains("badsite.org"));
        assert!(parsed.contains("malware.biz"));
        assert!(parsed.contains("telemetry.io"));
        assert!(parsed.contains("stats.telemetry.io"));
        assert!(parsed.contains("spy.net"));
        assert!(parsed.contains("analytics.com"));
        assert!(parsed.contains("*.wildcard-tracker.com"));
    }

    #[test]
    fn test_allowlist_filtering() {
        let content = "0.0.0.0 ad.com\n0.0.0.0 allowed.com\n";
        let mut parsed = parse_domain_list(content);

        let allow_tmp = "/tmp/albus_test_allow.tmp";
        fs::write(allow_tmp, "allowed.com\n").unwrap();
        let allow = parse_allowlist(allow_tmp);
        let _ = fs::remove_file(allow_tmp);

        parsed.retain(|d| !allow.contains(d));
        assert!(parsed.contains("ad.com"));
        assert!(!parsed.contains("allowed.com"));
    }
}
