// http 1.1 / http 2 request inspector, host header obfuscator, preface segmentation, and blockpage filter

pub struct HttpParser;

impl HttpParser {
    // checks if the buffer starts with a standard http request method
    pub fn is_http_request(buf: &[u8]) -> bool {
        let methods: &[&[u8]] = &[
            b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ",
        ];
        methods.iter().any(|m| buf.starts_with(m))
    }

    // checks for http/2 client connection magic preface (rfc 7540)
    pub fn is_http2_preface(buf: &[u8]) -> bool {
        buf.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    }

    // detects isp middlebox injected blockpage redirects (e.g. 302, 451, 403)
    #[allow(dead_code)]
    pub fn is_blockpage_response(buf: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(buf) {
            let lower = text.to_lowercase();
            if (lower.starts_with("http/1.1 302") || lower.starts_with("http/1.0 302") || lower.starts_with("http/1.1 451"))
                && lower.contains("location:")
                && (lower.contains("tib.gov.tr") || lower.contains("telekom") || lower.contains("blocked") || lower.contains("uyari"))
            {
                return true;
            }

        }
        false
    }

    // finds the host header byte range in the request buffer
    pub fn find_host_header(buf: &[u8]) -> Option<(usize, usize)> {
        let mut i = 0;
        let len = buf.len();

        while i + 6 <= len {
            let is_host = if i == 0 {
                buf[i..i + 5].eq_ignore_ascii_case(b"host:")
            } else if buf[i] == b'\n' && i + 6 <= len {
                buf[i + 1..i + 6].eq_ignore_ascii_case(b"host:")
            } else {
                false
            };

            if is_host {
                let start = if i == 0 { 0 } else { i + 1 };
                let mut end = start;
                while end < len && buf[end] != b'\r' && buf[end] != b'\n' {
                    end += 1;
                }
                return Some((start, end));
            }
            i += 1;
        }

        None
    }

    // mutates host header case (e.g. Host: -> hOsT:) and strips tracking headers
    pub fn mutate_and_sanitize_http_request(buf: &[u8]) -> Vec<u8> {
        let text = match std::str::from_utf8(buf) {
            Ok(s) => s,
            Err(_) => return buf.to_vec(),
        };

        let mut out = String::with_capacity(buf.len() + 16);
        for line in text.split("\r\n") {
            let lower = line.to_lowercase();
            if lower.starts_with("referer:")
                || lower.starts_with("x-forwarded-for:")
                || lower.starts_with("x-real-ip:")
                || lower.starts_with("client-ip:")
            {
                continue;
            }
            if lower.starts_with("host:") {
                // Obfuscate Host: to hOsT: (RFC 7230 case-insensitive header evasion)
                let val = &line[5..];
                out.push_str("hOsT:");
                out.push_str(val);
            } else {
                out.push_str(line);
            }
            out.push_str("\r\n");
        }

        if out.ends_with("\r\n\r\n") {
            out.into_bytes()
        } else {
            buf.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_preface() {
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert!(HttpParser::is_http2_preface(preface));
        assert!(!HttpParser::is_http2_preface(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_mutate_and_sanitize_headers() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nReferer: https://secret.local\r\nX-Forwarded-For: 1.2.3.4\r\nUser-Agent: Mozilla\r\n\r\n";
        let cleaned = HttpParser::mutate_and_sanitize_http_request(req);
        let cleaned_str = String::from_utf8(cleaned).unwrap();
        assert!(!cleaned_str.contains("Referer"));
        assert!(!cleaned_str.contains("X-Forwarded-For"));
        assert!(cleaned_str.contains("hOsT: example.com"));
        assert!(cleaned_str.contains("User-Agent: Mozilla"));
    }
}


