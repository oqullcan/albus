//! automated search engine safe-search and youtube restricted mode enforcement.
//!
//! transparently intercepts queries targeting major search providers (google, bing,
//! duckduckgo, yandex, youtube) and synthesizes dns responses pointing to family-safe
//! vip addresses and strict cnames.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YouTubeMode {
    None,
    Strict,
    Moderate,
}

impl YouTubeMode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "strict" => Self::Strict,
            "moderate" => Self::Moderate,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeSearchOverride {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Cname(&'static str),
}

const GOOGLE_SAFESEARCH_V4: Ipv4Addr = Ipv4Addr::new(216, 239, 38, 120);
const GOOGLE_SAFESEARCH_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4802, 0x32, 0, 0, 0, 0x78);

const YOUTUBE_STRICT_V4: Ipv4Addr = Ipv4Addr::new(216, 239, 38, 119);
const YOUTUBE_STRICT_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4802, 0x32, 0, 0, 0, 0x77);

const YOUTUBE_MODERATE_V4: Ipv4Addr = Ipv4Addr::new(216, 239, 38, 120);
const YOUTUBE_MODERATE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4802, 0x32, 0, 0, 0, 0x78);

const BING_SAFESEARCH_V4: Ipv4Addr = Ipv4Addr::new(204, 79, 197, 220);
const DUCKDUCKGO_SAFESEARCH_V4: Ipv4Addr = Ipv4Addr::new(52, 142, 124, 215);
const YANDEX_SAFESEARCH_V4: Ipv4Addr = Ipv4Addr::new(213, 180, 193, 56);

#[derive(Clone, Debug)]
pub struct SafeSearchEngine {
    pub safe_search: bool,
    pub youtube_mode: YouTubeMode,
}

impl SafeSearchEngine {
    pub fn new(safe_search: bool, youtube_mode: YouTubeMode) -> Self {
        Self {
            safe_search,
            youtube_mode,
        }
    }

    // inspects domain name and query type, returning an explicit safesearch override if applicable
    pub fn check(&self, domain: &str, qtype: u16) -> Option<SafeSearchOverride> {
        let clean = domain.trim().trim_end_matches('.').to_lowercase();

        // 1. YouTube Restricted Mode Check
        if self.youtube_mode != YouTubeMode::None && is_youtube_domain(&clean) {
            match self.youtube_mode {
                YouTubeMode::Strict => {
                    if qtype == 1 {
                        return Some(SafeSearchOverride::Ipv4(YOUTUBE_STRICT_V4));
                    } else if qtype == 28 {
                        return Some(SafeSearchOverride::Ipv6(YOUTUBE_STRICT_V6));
                    } else {
                        return Some(SafeSearchOverride::Cname("restrict.youtube.com"));
                    }
                }
                YouTubeMode::Moderate => {
                    if qtype == 1 {
                        return Some(SafeSearchOverride::Ipv4(YOUTUBE_MODERATE_V4));
                    } else if qtype == 28 {
                        return Some(SafeSearchOverride::Ipv6(YOUTUBE_MODERATE_V6));
                    } else {
                        return Some(SafeSearchOverride::Cname("restrictmoderate.youtube.com"));
                    }
                }
                YouTubeMode::None => {}
            }
        }

        if !self.safe_search {
            return None;
        }

        // 2. Google SafeSearch Check
        if is_google_search_domain(&clean) {
            if qtype == 1 {
                return Some(SafeSearchOverride::Ipv4(GOOGLE_SAFESEARCH_V4));
            } else if qtype == 28 {
                return Some(SafeSearchOverride::Ipv6(GOOGLE_SAFESEARCH_V6));
            } else {
                return Some(SafeSearchOverride::Cname("forcesafesearch.google.com"));
            }
        }

        // 3. Bing SafeSearch Check
        if clean == "bing.com" || clean == "www.bing.com" {
            if qtype == 1 {
                return Some(SafeSearchOverride::Ipv4(BING_SAFESEARCH_V4));
            } else {
                return Some(SafeSearchOverride::Cname("strict.bing.com"));
            }
        }

        // 4. DuckDuckGo SafeSearch Check
        if clean == "duckduckgo.com" || clean == "www.duckduckgo.com" {
            if qtype == 1 {
                return Some(SafeSearchOverride::Ipv4(DUCKDUCKGO_SAFESEARCH_V4));
            } else {
                return Some(SafeSearchOverride::Cname("safe.duckduckgo.com"));
            }
        }

        // 5. Yandex SafeSearch Check
        if clean == "yandex.ru"
            || clean == "yandex.com"
            || clean == "yandex.com.tr"
            || clean == "ya.ru"
        {
            if qtype == 1 {
                return Some(SafeSearchOverride::Ipv4(YANDEX_SAFESEARCH_V4));
            } else {
                return Some(SafeSearchOverride::Cname("familysearch.yandex.ru"));
            }
        }

        None
    }
}

fn is_google_search_domain(d: &str) -> bool {
    let clean = d.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean == "google.com" || clean == "www.google.com" {
        return true;
    }
    let parts: Vec<&str> = clean.split('.').collect();
    // Case 1: google.<ccTLD> (e.g. google.de, google.fr, google.ca)
    if parts.len() == 2 && parts[0] == "google" {
        return parts[1].len() == 2 || parts[1] == "cat";
    }
    // Case 2: www.google.<ccTLD> (e.g. www.google.de, www.google.it)
    if parts.len() == 3 && parts[0] == "www" && parts[1] == "google" {
        return parts[2].len() == 2 || parts[2] == "cat";
    }
    // Case 3: google.<sld>.<ccTLD> (e.g. google.co.uk, google.com.tr, google.co.jp)
    const VALID_SLDS: &[&str] = &["com", "co", "org", "net", "edu", "gov", "ac", "ne", "it"];
    if parts.len() == 3 && parts[0] == "google" {
        return VALID_SLDS.contains(&parts[1]) && parts[2].len() == 2;
    }
    // Case 4: www.google.<sld>.<ccTLD> (e.g. www.google.co.uk, www.google.com.tr)
    if parts.len() == 4 && parts[0] == "www" && parts[1] == "google" {
        return VALID_SLDS.contains(&parts[2]) && parts[3].len() == 2;
    }
    false
}

fn is_youtube_domain(d: &str) -> bool {
    d == "youtube.com"
        || d == "www.youtube.com"
        || d == "m.youtube.com"
        || d == "youtubei.googleapis.com"
        || d == "youtube.googleapis.com"
        || d == "youtube-nocookie.com"
        || d == "www.youtube-nocookie.com"
}

// synthesizes binary dns response packet encoding the safesearch override
pub fn build_safesearch_response(
    query: &[u8],
    domain: &str,
    qtype: u16,
    ovr: &SafeSearchOverride,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.len() + 32);

    if query.len() < 12 {
        return resp;
    }

    // Header
    resp.extend_from_slice(&query[0..2]); // tx id
    resp.extend_from_slice(&[0x81, 0x80]); // standard response, no error
    resp.extend_from_slice(&[0x00, 0x01]); // 1 question
    resp.extend_from_slice(&[0x00, 0x01]); // 1 answer
    resp.extend_from_slice(&[0x00, 0x00]); // 0 authority
    resp.extend_from_slice(&[0x00, 0x00]); // 0 additional

    // Copy Question section
    let mut pos = 12;
    while pos < query.len() && query[pos] != 0 {
        pos += 1 + query[pos] as usize;
    }
    pos += 1; // null byte
    pos += 4; // qtype + qclass
    if pos <= query.len() {
        resp.extend_from_slice(&query[12..pos]);
    } else {
        return Vec::new();
    }

    // Answer section
    resp.extend_from_slice(&[0xc0, 0x0c]); // pointer to QNAME

    match ovr {
        SafeSearchOverride::Ipv4(ip) => {
            resp.extend_from_slice(&[0x00, 0x01]); // type A
            resp.extend_from_slice(&[0x00, 0x01]); // class IN
            resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL = 300s
            resp.extend_from_slice(&[0x00, 0x04]); // rdlen = 4
            resp.extend_from_slice(&ip.octets());
        }
        SafeSearchOverride::Ipv6(ip) => {
            resp.extend_from_slice(&[0x00, 0x1c]); // type AAAA (28)
            resp.extend_from_slice(&[0x00, 0x01]); // class IN
            resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL = 300s
            resp.extend_from_slice(&[0x00, 0x10]); // rdlen = 16
            resp.extend_from_slice(&ip.octets());
        }
        SafeSearchOverride::Cname(cname) => {
            resp.extend_from_slice(&[0x00, 0x05]); // type CNAME (5)
            resp.extend_from_slice(&[0x00, 0x01]); // class IN
            resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL = 300s

            let mut cname_bytes = Vec::new();
            for part in cname.split('.') {
                if !part.is_empty() {
                    cname_bytes.push(part.len() as u8);
                    cname_bytes.extend_from_slice(part.as_bytes());
                }
            }
            cname_bytes.push(0x00);

            resp.extend_from_slice(&(cname_bytes.len() as u16).to_be_bytes());
            resp.extend_from_slice(&cname_bytes);
        }
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safesearch_google_and_bing() {
        let engine = SafeSearchEngine::new(true, YouTubeMode::None);

        let google_a = engine.check("www.google.com", 1);
        assert_eq!(
            google_a,
            Some(SafeSearchOverride::Ipv4(GOOGLE_SAFESEARCH_V4))
        );

        let google_aaaa = engine.check("google.com.tr", 28);
        assert_eq!(
            google_aaaa,
            Some(SafeSearchOverride::Ipv6(GOOGLE_SAFESEARCH_V6))
        );

        let google_uk = engine.check("www.google.co.uk", 1);
        assert_eq!(
            google_uk,
            Some(SafeSearchOverride::Ipv4(GOOGLE_SAFESEARCH_V4))
        );

        // Non-search Google domains must not be redirected
        assert_eq!(engine.check("google.golang.org", 1), None);
        assert_eq!(engine.check("google.dev", 1), None);
        assert_eq!(engine.check("mail.google.com", 1), None);

        let bing_a = engine.check("www.bing.com", 1);
        assert_eq!(bing_a, Some(SafeSearchOverride::Ipv4(BING_SAFESEARCH_V4)));

        let duck_a = engine.check("duckduckgo.com", 1);
        assert_eq!(
            duck_a,
            Some(SafeSearchOverride::Ipv4(DUCKDUCKGO_SAFESEARCH_V4))
        );

        let unrelated = engine.check("github.com", 1);
        assert_eq!(unrelated, None);
    }

    #[test]
    fn test_youtube_restricted_modes() {
        let engine_strict = SafeSearchEngine::new(false, YouTubeMode::Strict);
        let yt_strict = engine_strict.check("www.youtube.com", 1);
        assert_eq!(yt_strict, Some(SafeSearchOverride::Ipv4(YOUTUBE_STRICT_V4)));
        let yt_nocookie = engine_strict.check("youtube-nocookie.com", 1);
        assert_eq!(
            yt_nocookie,
            Some(SafeSearchOverride::Ipv4(YOUTUBE_STRICT_V4))
        );

        let engine_moderate = SafeSearchEngine::new(false, YouTubeMode::Moderate);
        let yt_moderate = engine_moderate.check("youtube.com", 1);
        assert_eq!(
            yt_moderate,
            Some(SafeSearchOverride::Ipv4(YOUTUBE_MODERATE_V4))
        );
    }

    #[test]
    fn test_build_safesearch_response_packet() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 6, b'g', b'o',
            b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        ];
        let ovr = SafeSearchOverride::Ipv4(GOOGLE_SAFESEARCH_V4);
        let resp = build_safesearch_response(&query, "google.com", 1, &ovr);
        assert!(resp.len() > query.len());
        assert_eq!(&resp[0..2], &[0x12, 0x34]);
        assert_eq!(&resp[2..4], &[0x81, 0x80]);
        assert_eq!(&resp[resp.len() - 4..], &GOOGLE_SAFESEARCH_V4.octets());
    }
}
