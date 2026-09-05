//! http/1.1 request detection, method pipeline splitting, and decoy request generation.
//!
//! desynchronizes deep packet inspection engines analyzing cleartext port 80 http traffic
//! by fragmenting request verbs (e.g. 'G' + 'ET /') and injecting fake benign http headers.

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"CONNECT ",
];

// detects whether a byte slice begins with a standard RFC 7230 HTTP request method
pub fn is_http_payload(data: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|&method| data.starts_with(method))
}

// splits an HTTP request after the first byte of the verb (e.g. 'G' and 'ET / HTTP/1.1...')
// forcing stateful DPI middleboxes to fail regex/pattern matches across packet boundaries
pub fn split_http_request(req: &[u8]) -> (&[u8], &[u8]) {
    if req.is_empty() {
        return (&[], &[]);
    }
    // split after the first byte of the method (e.g. 'G' and 'ET...')
    req.split_at(1.min(req.len()))
}

// builds a realistic synthetic decoy HTTP GET request targeting a benign domain
pub fn build_fake_http_request(host: &str) -> Vec<u8> {
    let clean_host = if host.is_empty() {
        "www.google.com"
    } else {
        host
    };
    format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: keep-alive\r\n\r\n",
        clean_host
    ).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_payload() {
        assert!(is_http_payload(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ));
        assert!(is_http_payload(b"POST /api/v1/data HTTP/1.1\r\n"));
        assert!(is_http_payload(b"HEAD / HTTP/1.1\r\n"));

        // non-http payloads
        assert!(!is_http_payload(&[0x16, 0x03, 0x01, 0x00, 0xa0])); // TLS ClientHello
        assert!(!is_http_payload(b"SSH-2.0-OpenSSH_9.0\r\n"));
        assert!(!is_http_payload(&[]));
    }

    #[test]
    fn test_split_http_request() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (first, second) = split_http_request(req);
        assert_eq!(first, b"G");
        assert_eq!(second, b"ET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

        let (empty_1, empty_2) = split_http_request(&[]);
        assert!(empty_1.is_empty());
        assert!(empty_2.is_empty());
    }

    #[test]
    fn test_build_fake_http_request() {
        let fake = build_fake_http_request("www.wikipedia.org");
        assert!(fake.starts_with(b"GET / HTTP/1.1\r\nHost: www.wikipedia.org\r\n"));
        assert!(fake.ends_with(b"\r\n\r\n"));

        let default_fake = build_fake_http_request("");
        assert!(default_fake
            .windows(b"Host: www.google.com".len())
            .any(|w| w == b"Host: www.google.com"));
    }
}
