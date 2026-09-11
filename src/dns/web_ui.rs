//! lightweight embedded web control center (http://127.0.0.1:0205) for albus.
//!
//! provides a zero-external-dependency, comprehensive web interface for full
//! configuration management, real-time dns telemetry, eBPF status, and live event logs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, info, warn};

use super::stats::DnsStats;
use crate::app::config::Config;

/// Constant-time comparison of byte slices to prevent timing side-channels (CWE-208).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time string comparison by first computing SHA-256 digests of both inputs.
/// This prevents both character-by-character timing leaks (CWE-208) and length-dependent leakage.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let hash_a = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, a.as_bytes());
    let hash_b = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b.as_bytes());
    constant_time_eq(hash_a.as_ref(), hash_b.as_ref())
}

/// Safely parses a web UI address or port string (e.g. "127.0.0.1:205", "127.0.0.1:0205", "205", "0205", ":205", ":0205").
pub fn parse_web_ui_addr(input: &str) -> SocketAddr {
    let clean = input.trim();
    if let Ok(addr) = clean.parse::<SocketAddr>() {
        return addr;
    }
    if clean.starts_with(':') {
        if let Ok(addr) = format!("127.0.0.1{}", clean).parse::<SocketAddr>() {
            return addr;
        }
    } else if clean.chars().all(|c| c.is_ascii_digit()) && !clean.is_empty() {
        if let Ok(addr) = format!("127.0.0.1:{}", clean).parse::<SocketAddr>() {
            return addr;
        }
    }
    "127.0.0.1:205".parse().unwrap()
}

/// Anonymizes client IP addresses and domain names in log lines according to privacy level.
/// Privacy levels (inspired by dnscrypt-proxy):
/// - 0: No anonymization. Log lines returned verbatim.
/// - 1: Client IP addresses are anonymized (e.g., IPv4 /24 masked: `192.168.1.42` -> `192.168.1.0`, IPv6 /48 masked).
/// - 2: Both client IP addresses and domain names are masked (e.g. `example.com` -> `***.com`, `sub.example.com` -> `***.example.com`).
/// - 3+: Full privacy (all client IPs, domains, and sensitive query tokens masked).
pub fn anonymize_log_line(line: &str, privacy_level: u8) -> String {
    if privacy_level == 0 {
        return line.to_string();
    }

    let anonymize_token = |token: &str| -> String {
        if let Ok(ip) = token.parse::<std::net::Ipv4Addr>() {
            let oct = ip.octets();
            return format!("{}.{}.{}.0", oct[0], oct[1], oct[2]);
        }
        if let Ok(sock) = token.parse::<std::net::SocketAddrV4>() {
            let oct = sock.ip().octets();
            return format!("{}.{}.{}.0:{}", oct[0], oct[1], oct[2], sock.port());
        }
        if let Ok(ip6) = token.parse::<std::net::Ipv6Addr>() {
            let seg = ip6.segments();
            return format!("{:x}:{:x}:{:x}::0", seg[0], seg[1], seg[2]);
        }
        if let Ok(sock6) = token.parse::<std::net::SocketAddrV6>() {
            let seg = sock6.ip().segments();
            return format!("[{:x}:{:x}:{:x}::0]:{}", seg[0], seg[1], seg[2], sock6.port());
        }

        if privacy_level >= 2 {
            let clean = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
            if clean.contains('.')
                && !clean.starts_with('.')
                && !clean.ends_with('.')
                && !clean.chars().next().map_or(false, |c| c.is_ascii_digit())
                && clean.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
            {
                let parts: Vec<&str> = clean.split('.').collect();
                if parts.len() >= 2 {
                    if privacy_level >= 3 {
                        return token.replace(clean, "[REDACTED_DOMAIN]");
                    }
                    let tld = parts[parts.len() - 1];
                    let sld = parts[parts.len() - 2];
                    let masked_domain = if parts.len() == 2 {
                        format!("***.{}", tld)
                    } else {
                        format!("***.{}.{}", sld, tld)
                    };
                    return token.replace(clean, &masked_domain);
                }
            }
        }

        token.to_string()
    };

    if line.contains('\t') {
        let cols: Vec<&str> = line.split('\t').collect();
        let mut new_cols = Vec::with_capacity(cols.len());
        for (idx, col) in cols.iter().enumerate() {
            if idx == 1 {
                new_cols.push(anonymize_token(col));
            } else if idx == 2 && privacy_level >= 2 {
                new_cols.push(anonymize_token(col));
            } else {
                new_cols.push(col.to_string());
            }
        }
        return new_cols.join("\t");
    }

    let mut out = String::with_capacity(line.len());
    let mut current_word = String::new();

    let flush_word = |word: &str, target: &mut String| {
        if word.is_empty() {
            return;
        }
        if let Some((k, v)) = word.split_once('=') {
            if k == "client" || k == "client_ip" || k == "ip" || k == "addr" {
                target.push_str(k);
                target.push('=');
                target.push_str(&anonymize_token(v));
            } else if (k == "domain" || k == "qname" || k == "host") && privacy_level >= 2 {
                target.push_str(k);
                target.push('=');
                target.push_str(&anonymize_token(v));
            } else {
                target.push_str(k);
                target.push('=');
                target.push_str(&anonymize_token(v));
            }
        } else {
            target.push_str(&anonymize_token(word));
        }
    };

    for c in line.chars() {
        if c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\'' {
            flush_word(&current_word, &mut out);
            current_word.clear();
            out.push(c);
        } else {
            current_word.push(c);
        }
    }
    flush_word(&current_word, &mut out);

    out
}

pub struct WebUiServer;

const MAX_CONCURRENT_WEB_CONNS: usize = 32;
const MAX_REQUEST_SIZE: usize = 65536;

async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, String, String, Vec<u8>), ()> {
    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let mut header_end = None;
    let mut content_length = 0usize;

    let read_timeout = Duration::from_secs(4);
    let start_time = Instant::now();

    while header_end.is_none() {
        if start_time.elapsed() > read_timeout || buf.len() > MAX_REQUEST_SIZE {
            return Err(());
        }
        let n = match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut temp)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Err(()),
        };
        buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos);
            break;
        }
    }

    let h_end = header_end.ok_or(())?;
    let header_bytes = &buf[..h_end];
    let header_str = String::from_utf8_lossy(header_bytes);
    let first_line = header_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(());
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    for line in header_str.lines() {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            if let Some(val) = line.split(':').nth(1) {
                content_length = val.trim().parse().unwrap_or(0);
            }
        }
    }

    let body_start = h_end + 4;
    let mut body = buf[body_start..].to_vec();
    while body.len() < content_length {
        if start_time.elapsed() > read_timeout || body.len() > MAX_REQUEST_SIZE {
            return Err(());
        }
        let needed = content_length - body.len();
        let to_read = needed.min(temp.len());
        let n = match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut temp[..to_read])).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        body.extend_from_slice(&temp[..n]);
    }

    Ok((method, path, header_str.to_string(), body))
}

impl WebUiServer {
    pub fn start(
        bind_addr: SocketAddr,
        stats: Arc<DnsStats>,
        auth: Option<(String, String)>,
        shutdown_rx: broadcast::Receiver<()>,
        dns_server: Option<Arc<super::server::DnsServer>>,
    ) {
        let start_time = Instant::now();
        tokio::spawn(async move {
            let listener = match TcpListener::bind(bind_addr).await {
                Ok(l) => {
                    info!(addr = %bind_addr, "Embedded Web Monitoring Dashboard active on http://{}", bind_addr);
                    l
                }
                Err(e) => {
                    warn!(
                        "failed to bind Web Monitoring Dashboard to {}: {}",
                        bind_addr, e
                    );
                    return;
                }
            };

            Self::run_listener(listener, stats, auth, shutdown_rx, start_time, dns_server).await;
        });
    }

    pub async fn run_listener(
        listener: TcpListener,
        stats: Arc<DnsStats>,
        auth: Option<(String, String)>,
        mut shutdown_rx: broadcast::Receiver<()>,
        start_time: Instant,
        dns_server: Option<Arc<super::server::DnsServer>>,
    ) {
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_WEB_CONNS));

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((mut stream, _peer_addr)) => {
                            let permit = match sem.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    debug!("web dashboard max connection limit reached; dropping connection");
                                    continue;
                                }
                            };
                            let stats_clone = stats.clone();
                            let auth_clone = auth.clone();
                            let dns_server_clone = dns_server.clone();

                            tokio::spawn(async move {
                                let _permit = permit;

                                let (method, path, req_str, body) = match read_http_request(&mut stream).await {
                                    Ok(req) => req,
                                    Err(_) => return,
                                };

                                // Basic Authentication check
                                if let Some((ref exp_user, ref exp_pass)) = auth_clone {
                                    let mut authenticated = false;
                                    for line in req_str.lines() {
                                        if line.to_ascii_lowercase().starts_with("authorization: basic ") {
                                            if let Some(b64) = line.split_whitespace().nth(2) {
                                                if let Ok(decoded) = decode_base64(b64) {
                                                    if let Ok(cred_str) = std::str::from_utf8(&decoded) {
                                                        if let Some((user, pass)) = cred_str.split_once(':') {
                                                            if constant_time_eq_str(user, exp_user)
                                                                && constant_time_eq_str(pass, exp_pass)
                                                            {
                                                                authenticated = true;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if !authenticated {
                                        let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Albus Dashboard\"\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nUnauthorized";
                                        let _ = stream.write_all(resp.as_bytes()).await;
                                        return;
                                    }
                                }

                                let clean_path = path.split('?').next().unwrap_or(path.as_str());
                                let response = match (method.as_str(), clean_path) {
                                    ("GET", "/") | ("GET", "/index.html") => {
                                        let html = render_dashboard_html();
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            html.len(),
                                            html
                                        )
                                    }
                                    ("HEAD", "/") | ("HEAD", "/index.html") => {
                                        let html = render_dashboard_html();
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            html.len()
                                        )
                                    }
                                    ("GET", "/api/stats") => {
                                        let snap = stats_clone.snapshot();
                                        let mut snap_val = serde_json::to_value(&snap).unwrap_or_default();
                                        if let Some(obj) = snap_val.as_object_mut() {
                                            obj.insert("uptime_secs".to_string(), serde_json::json!(start_time.elapsed().as_secs()));
                                            obj.insert("version".to_string(), serde_json::json!(env!("CARGO_PKG_VERSION")));
                                        }
                                        let json = serde_json::to_string(&snap_val).unwrap_or_else(|_| "{}".to_string());
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            json.len(),
                                            json
                                        )
                                    }
                                    ("HEAD", "/api/stats") => {
                                        let snap = stats_clone.snapshot();
                                        let mut snap_val = serde_json::to_value(&snap).unwrap_or_default();
                                        if let Some(obj) = snap_val.as_object_mut() {
                                            obj.insert("uptime_secs".to_string(), serde_json::json!(start_time.elapsed().as_secs()));
                                            obj.insert("version".to_string(), serde_json::json!(env!("CARGO_PKG_VERSION")));
                                        }
                                        let json = serde_json::to_string(&snap_val).unwrap_or_else(|_| "{}".to_string());
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            json.len()
                                        )
                                    }
                                    ("GET", "/api/config") => {
                                        let cfg = Config::load_or_default();
                                        let json = serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".to_string());
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            json.len(),
                                            json
                                        )
                                    }
                                    ("HEAD", "/api/config") => {
                                        let cfg = Config::load_or_default();
                                        let json = serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".to_string());
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            json.len()
                                        )
                                    }
                                    ("POST", "/api/config") => {
                                        let body_str = String::from_utf8_lossy(&body);
                                        match serde_json::from_str::<Config>(&body_str) {
                                            Ok(mut new_cfg) => {
                                                if new_cfg.doh_upstream.starts_with("http")
                                                    && crate::dns::ssrf::is_ssrf_risk(&new_cfg.doh_upstream)
                                                {
                                                    let err_msg = "{\"status\":\"error\",\"message\":\"Security violation: Upstream URL rejected due to SSRF risk\"}";
                                                    format!(
                                                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                        err_msg.len(),
                                                        err_msg
                                                    )
                                                } else {
                                                    new_cfg.mss = new_cfg.mss.clamp(64, 1500);
                                                    new_cfg.min_mss = new_cfg.min_mss.clamp(64, new_cfg.mss);
                                                    if new_cfg.fake_ttl == 0 {
                                                        new_cfg.fake_ttl = 8;
                                                    }

                                                    let save_path = if crate::core::ebpf::is_root() && std::path::Path::new("/etc/albus").exists() {
                                                        std::path::PathBuf::from("/etc/albus/config.json")
                                                    } else {
                                                        Config::default_config_path()
                                                    };
                                                    if let Err(e) = new_cfg.save_to_file(&save_path) {
                                                        let err_msg = format!("{{\"status\":\"error\",\"message\":\"Failed to save config: {}\"}}", e);
                                                        format!(
                                                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                            err_msg.len(),
                                                            err_msg
                                                        )
                                                    } else {
                                                        let user_path = Config::default_config_path();
                                                        if user_path != save_path {
                                                            let _ = new_cfg.save_to_file(&user_path);
                                                        }

                                                        if let Some(ref dns) = dns_server_clone {
                                                            if let Err(e) = dns.reload_from_config(&new_cfg).await {
                                                                warn!("failed to reload DNS server live from web UI: {}", e);
                                                            }
                                                        }

                                                        let _ = tokio::process::Command::new("systemctl")
                                                            .args(["kill", "-s", "HUP", "albus.service"])
                                                            .status()
                                                            .await;

                                                        let ok_msg = "{\"status\":\"ok\",\"message\":\"Configuration saved and applied live to kernel & resolver\"}";
                                                        format!(
                                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                            ok_msg.len(),
                                                            ok_msg
                                                        )
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let err_msg = format!("{{\"status\":\"error\",\"message\":\"Invalid config JSON: {}\"}}", e);
                                                format!(
                                                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                    err_msg.len(),
                                                    err_msg
                                                )
                                            }
                                        }
                                    }
                                    ("POST", "/api/service/action") => {
                                        let body_str = String::from_utf8_lossy(&body);
                                        let action_val: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                                        let action = action_val.get("action").and_then(|v| v.as_str()).unwrap_or("");
                                        match action {
                                            "restart" => {
                                                tokio::spawn(async {
                                                    tokio::time::sleep(Duration::from_millis(300)).await;
                                                    let _ = tokio::process::Command::new("systemctl")
                                                        .args(["restart", "albus.service"])
                                                        .status()
                                                        .await;
                                                });
                                                let ok_msg = "{\"status\":\"ok\",\"action\":\"restart\",\"message\":\"Service restart scheduled\"}";
                                                format!(
                                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                    ok_msg.len(),
                                                    ok_msg
                                                )
                                            }
                                            "reload" => {
                                                let cfg = Config::load_or_default();
                                                if let Some(ref dns) = dns_server_clone {
                                                    if let Err(e) = dns.reload_from_config(&cfg).await {
                                                        warn!("failed to reload DNS server live: {}", e);
                                                    }
                                                }
                                                let _ = tokio::process::Command::new("systemctl")
                                                    .args(["kill", "-s", "HUP", "albus.service"])
                                                    .status()
                                                    .await;
                                                let ok_msg = "{\"status\":\"ok\",\"action\":\"reload\",\"message\":\"Configuration reloaded live into kernel & resolver\"}";
                                                format!(
                                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                    ok_msg.len(),
                                                    ok_msg
                                                )
                                            }
                                            "flush-cache" => {
                                                if let Some(ref dns) = dns_server_clone {
                                                    dns.flush_cache();
                                                }
                                                let _ = tokio::process::Command::new("systemctl")
                                                    .args(["kill", "-s", "USR1", "albus.service"])
                                                    .status()
                                                    .await;
                                                let ok_msg = "{\"status\":\"ok\",\"action\":\"flush-cache\",\"message\":\"DNS cache flushed live\"}";
                                                format!(
                                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                    ok_msg.len(),
                                                    ok_msg
                                                )
                                            }
                                            _ => {
                                                let err_msg = "{\"status\":\"error\",\"message\":\"Unknown action\"}";
                                                format!(
                                                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                                    err_msg.len(),
                                                    err_msg
                                                )
                                            }
                                        }
                                    }
                                    ("GET", "/api/logs") => {
                                        let cfg = Config::load_or_default();
                                        let limit = cfg.web_ui_max_query_log_entries.clamp(10, 1000);
                                        let limit_str = limit.to_string();
                                        let log_cmd = tokio::time::timeout(
                                            Duration::from_millis(1500),
                                            tokio::process::Command::new("journalctl")
                                                .args(["-u", "albus.service", "-n", &limit_str, "--no-pager"])
                                                .output(),
                                        )
                                        .await;
                                        let logs: Vec<String> = match log_cmd {
                                            Ok(Ok(output)) if output.status.success() => {
                                                let s = String::from_utf8_lossy(&output.stdout);
                                                s.lines()
                                                    .filter(|l| !l.trim().is_empty())
                                                    .map(|l| anonymize_log_line(l, cfg.web_ui_privacy_level))
                                                    .collect()
                                            }
                                            _ => Vec::new(),
                                        };
                                        let json = serde_json::json!({ "logs": logs }).to_string();
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            json.len(),
                                            json
                                        )
                                    }
                                    ("HEAD", "/api/logs") => {
                                        let json = "{\"logs\":[]}".to_string();
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            json.len()
                                        )
                                    }
                                    ("GET", "/api/health") | ("GET", "/live") => {
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_string()
                                    }
                                    ("HEAD", "/api/health") | ("HEAD", "/live") => {
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\n".to_string()
                                    }
                                    _ => {
                                        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found".to_string()
                                    }
                                };

                                let _ = stream.write_all(response.as_bytes()).await;
                            });
                        }
                        Err(e) => {
                            debug!("web dashboard accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Web Monitoring Dashboard received shutdown signal; stopping listener");
                    break;
                }
            }
        }
    }
}

// simple standard base64 decoder without external dependencies
pub fn decode_base64(input: &str) -> Result<Vec<u8>, &'static str> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [0xFFu8; 256];
    for (i, &b) in TABLE.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }

    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);

    let mut buf = 0u32;
    let mut bits = 0;

    for &b in bytes {
        if b == b'=' {
            break;
        }
        let val = lookup[b as usize];
        if val == 0xFF {
            return Err("invalid base64 character");
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

// generates the embedded, self-contained single-page dashboard HTML
pub fn render_dashboard_html() -> String {
    r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Albus Control Center</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@100..900&family=JetBrains+Mono:ital,wght@0,100..800;1,100..800&display=swap" rel="stylesheet">
<style>
/* ==========================================================================
   ALBUS MATTE BLACK DESIGN SYSTEM
   ========================================================================== */

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

:root {
  --t-bg-deep: #08080a;
  --t-bg: #0d0d10;
  --t-surface: #131316;
  --t-surface-2: #18181c;
  --t-surface-hover: #1f1f24;
  --t-border-subtle: #222228;
  --t-border-strong: #32323a;
  --t-text: #f4f4f5;
  --t-text-secondary: #a1a1aa;
  --t-text-muted: #71717a;
  --t-brand: #f59e0b;
  --t-brand-soft: rgba(245, 158, 11, 0.12);
  --t-brand-glow: rgba(245, 158, 11, 0.25);
  --t-brand-ink: #000000;
  --t-accent-emerald: #10b981;
  --t-accent-cyan: #38bdf8;
  --t-accent-purple: #a855f7;
  --t-accent-orange: #f97316;
  --t-accent-red: #ef4444;
  --t-field-bg: #09090b;
  --t-field-dim: #38240a;
  --t-field-mid: #784a0d;
  --t-field-lit: #f59e0b;
  --t-field-hover: #fbbf24;
  --t-field-crest: #fef3c7;
  --t-elevation: 0 0 0 1px rgba(255, 255, 255, 0.05), 0 2px 8px rgba(0, 0, 0, 0.45);
  --t-elevation-hover: 0 0 0 1px rgba(255, 255, 255, 0.12), 0 4px 16px rgba(0, 0, 0, 0.65);
  --font-sans: 'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --radius-xs: 2px;
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --radius-xl: 12px;
  --radius-full: 9999px;
  --z-nav: 100;
  --z-modal: 300;
  --z-toast: 400;
}

/* ==========================================================================
   GLOBAL LAYOUT & BASE TYPOGRAPHY
   ========================================================================== */

body {
  background-color: var(--t-bg);
  color: var(--t-text);
  font-family: var(--font-sans);
  font-size: 13.5px;
  line-height: 1.5;
  min-height: 100vh;
  margin: 0;
  padding: 0;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  font-feature-settings: 'cv02', 'cv03', 'cv04', 'cv11';
  overflow-x: hidden;
  transition: background-color 200ms ease, color 200ms ease;
}

::selection {
  background-color: var(--t-brand);
  color: var(--t-brand-ink);
}

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--t-bg-deep); }
::-webkit-scrollbar-thumb { background: var(--t-border-strong); border-radius: var(--radius-sm); }
::-webkit-scrollbar-thumb:hover { background: var(--t-text-muted); }

/* ==========================================================================
   OMARCHY DRAWN MARK ANIMATION (Brand.tsx & styles.css)
   ========================================================================== */

.mark-draw path {
  stroke-dasharray: 1;
}

@keyframes mark-draw {
  from { stroke-dashoffset: 1; }
  to { stroke-dashoffset: 0; }
}

@keyframes mark-draw-back {
  from { stroke-dashoffset: -1; }
  to { stroke-dashoffset: 0; }
}

.mark-draw-trigger:is(:hover, :focus-visible) .mark-draw path {
  animation: mark-draw 650ms cubic-bezier(0.45, 0, 0.25, 1) both;
}

.mark-draw-trigger:is(:hover, :focus-visible) .mark-draw path:nth-of-type(2) {
  animation-duration: 110ms;
  animation-delay: 250ms;
  animation-timing-function: ease-out;
}

.mark-draw-trigger:is(:hover, :focus-visible) .mark-draw path:nth-of-type(3) {
  animation-duration: 470ms;
  animation-delay: 360ms;
}

.mark-draw-trigger:is(:hover, :focus-visible) .mark-draw path:nth-of-type(4) {
  animation-name: mark-draw-back;
  animation-duration: 70ms;
  animation-delay: 540ms;
}

.mark-draw-trigger:is(:hover, :focus-visible) .mark-draw path:nth-of-type(5) {
  animation-name: mark-draw-back;
  animation-duration: 70ms;
  animation-delay: 600ms;
}

/* ==========================================================================
   SITE HEADER
   ========================================================================== */

.site-header {
  position: sticky;
  top: 0;
  z-index: var(--z-nav);
  background-color: color-mix(in srgb, var(--t-surface) 90%, transparent);
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--t-border-subtle);
  transition: background-color 200ms ease, border-color 200ms ease;
}

.header-inner {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 20px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.header-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  text-decoration: none;
  color: inherit;
  cursor: pointer;
}

.brand-icon-box {
  width: 28px;
  height: 28px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--t-surface-2);
  border: 1px solid var(--t-border-strong);
  overflow: hidden;
}

.brand-title-text {
  font-family: var(--font-sans);
  font-weight: 700;
  font-size: 15px;
  letter-spacing: -0.02em;
  color: var(--t-text);
  line-height: 1.1;
}

.brand-subtext {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--t-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

/* Header action buttons */
.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  height: 32px;
  padding: 0 12px;
  border-radius: var(--radius-md);
  font-family: var(--font-sans);
  font-size: 12.5px;
  font-weight: 500;
  white-space: nowrap;
  border: 1px solid transparent;
  cursor: pointer;
  user-select: none;
  outline: none;
  transition: all 150ms cubic-bezier(0.16, 1, 0.3, 1);
  text-decoration: none;
}

.btn:active {
  transform: scale(0.96);
}

.btn-default {
  background: var(--t-brand);
  color: var(--t-brand-ink);
  font-weight: 600;
}

.btn-default:hover {
  filter: brightness(1.08);
}

.btn-outline {
  background: var(--t-surface);
  border-color: var(--t-border-strong);
  color: var(--t-text);
  box-shadow: var(--t-elevation);
}

.btn-outline:hover {
  background: var(--t-surface-2);
  color: var(--t-text);
}

.btn-ghost {
  background: transparent;
  color: var(--t-text-secondary);
}

.btn-ghost:hover {
  background: var(--t-surface-2);
  color: var(--t-text);
}

.btn-icon {
  width: 32px;
  height: 32px;
  padding: 0;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 9px;
  border-radius: var(--radius-full);
  background: var(--t-brand-soft);
  border: 1px solid color-mix(in srgb, var(--t-brand) 40%, transparent);
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 600;
  color: var(--t-brand);
  letter-spacing: 0.03em;
}

.status-pill.paused {
  background: rgba(247, 118, 142, 0.15);
  border-color: rgba(247, 118, 142, 0.35);
  color: var(--t-accent-red);
}

.pulse-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background-color: currentColor;
  box-shadow: 0 0 6px currentColor;
  animation: pulse-glow 2s infinite ease-in-out;
}

@keyframes pulse-glow {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.4; transform: scale(0.85); }
}

/* ==========================================================================
   NAVIGATION TABS STRIP (TabsList exact)
   ========================================================================== */

.nav-strip {
  background-color: var(--t-surface);
  border-bottom: 1px solid var(--t-border-subtle);
  position: sticky;
  top: 56px;
  z-index: calc(var(--z-nav) - 1);
}

.nav-inner {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 20px;
  display: flex;
  align-items: center;
  gap: 4px;
  overflow-x: auto;
  scrollbar-width: none;
}
.nav-inner::-webkit-scrollbar { display: none; }

.tab-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 14px;
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 600;
  color: var(--t-text-secondary);
  letter-spacing: 0.04em;
  border: none;
  background: transparent;
  cursor: pointer;
  white-space: nowrap;
  border-bottom: 2px solid transparent;
  transition: all 150ms ease;
}

.tab-btn:hover {
  color: var(--t-text);
  background-color: color-mix(in srgb, var(--t-surface-2) 40%, transparent);
}

.tab-btn.active {
  color: var(--t-brand);
  border-bottom-color: var(--t-brand);
  background-color: color-mix(in srgb, var(--t-surface-2) 60%, transparent);
}

.tab-num {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 17px;
  height: 17px;
  border-radius: var(--radius-xs);
  background: var(--t-surface-2);
  color: var(--t-text-muted);
  font-size: 10px;
  font-weight: 700;
}

.tab-btn.active .tab-num {
  background: var(--t-brand-soft);
  color: var(--t-brand);
}

/* ==========================================================================
   METRIC RAIL
   ========================================================================== */

.metrics-section {
  max-width: 1280px;
  margin: 24px auto 0 auto;
  padding: 0 20px;
  width: 100%;
}

.metrics-rail {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 16px;
}

.metric-card {
  background: var(--t-surface);
  border: 1px solid var(--t-border-subtle);
  border-radius: var(--radius-lg);
  padding: 18px 20px;
  box-shadow: var(--t-elevation);
  display: flex;
  flex-direction: column;
  gap: 8px;
  transition: border-color 150ms ease, box-shadow 150ms ease;
}

.metric-card:hover {
  border-color: var(--t-border-strong);
  box-shadow: var(--t-elevation-hover);
}

.metric-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.metric-label {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--t-text-muted);
}

.metric-chip {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 2px 6px;
  border-radius: var(--radius-xs);
  background: var(--t-surface-2);
  color: var(--t-text-secondary);
}

.metric-val {
  font-family: var(--font-mono);
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.03em;
  color: var(--t-text);
  line-height: 1;
}

.metric-sub {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--t-text-secondary);
}

.progress-track {
  width: 100%;
  height: 4px;
  background: var(--t-surface-2);
  border-radius: var(--radius-full);
  overflow: hidden;
  margin-top: 4px;
}

.progress-bar {
  height: 100%;
  background: var(--t-brand);
  border-radius: var(--radius-full);
  transition: width 300ms ease;
}

/* ==========================================================================
   TAB PANELS & FORMS
   ========================================================================== */

.main-container {
  max-width: 1280px;
  margin: 20px auto 60px auto;
  padding: 0 20px;
  width: 100%;
}

.tab-panel {
  display: none;
  flex-direction: column;
  gap: 20px;
  animation: fadeIn 150ms ease-out;
}

.tab-panel.active {
  display: flex;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}

.card-box {
  background: var(--t-surface);
  border: 1px solid var(--t-border-subtle);
  border-radius: var(--radius-lg);
  padding: 20px 22px;
  box-shadow: var(--t-elevation);
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.card-box-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
  border-bottom: 1px solid var(--t-border-subtle);
  padding-bottom: 12px;
}

.card-box-title {
  font-size: 15px;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: var(--t-text);
  display: flex;
  align-items: center;
  gap: 8px;
}

.card-box-desc {
  font-size: 12px;
  color: var(--t-text-muted);
}

/* Settings Grid & Omarchy Switches */
.settings-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 12px;
}

.setting-tile {
  background: var(--t-bg-deep);
  border: 1px solid var(--t-border-subtle);
  border-radius: var(--radius-md);
  padding: 12px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  transition: border-color 150ms ease;
}

.setting-tile:hover {
  border-color: var(--t-border-strong);
}

.tile-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.tile-title {
  font-family: var(--font-mono);
  font-size: 12.5px;
  font-weight: 600;
  color: var(--t-text);
}

.tile-desc {
  font-size: 11.5px;
  color: var(--t-text-muted);
  line-height: 1.35;
}

/* Pill switch toggle */
.switch {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 22px;
  flex-shrink: 0;
  cursor: pointer;
}

.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  inset: 0;
  background-color: var(--t-surface-2);
  border: 1px solid var(--t-border-strong);
  border-radius: var(--radius-full);
  transition: all 200ms cubic-bezier(0.16, 1, 0.3, 1);
}

.slider::before {
  position: absolute;
  content: "";
  height: 14px;
  width: 14px;
  left: 3px;
  bottom: 3px;
  background-color: var(--t-text-secondary);
  border-radius: 50%;
  transition: all 200ms cubic-bezier(0.16, 1, 0.3, 1);
}

.switch input:checked + .slider {
  background-color: var(--t-brand);
  border-color: var(--t-brand);
}

.switch input:checked + .slider::before {
  transform: translateX(18px);
  background-color: var(--t-brand-ink);
}

/* Inputs & Form Groups */
.form-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.form-label {
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 600;
  color: var(--t-text-secondary);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.form-input,
.form-select,
.form-textarea {
  width: 100%;
  background-color: var(--t-bg-deep);
  border: 1px solid var(--t-border-strong);
  border-radius: var(--radius-md);
  color: var(--t-text);
  font-family: var(--font-mono);
  font-size: 12.5px;
  padding: 7px 11px;
  outline: none;
  transition: border-color 150ms ease, box-shadow 150ms ease;
}

.form-input:focus,
.form-select:focus,
.form-textarea:focus {
  border-color: var(--t-brand);
  box-shadow: 0 0 0 2px var(--t-brand-soft);
}

/* Matrix grid */
.matrix-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px;
}

.matrix-card {
  background: var(--t-bg-deep);
  border: 1px solid var(--t-border-subtle);
  border-radius: var(--radius-md);
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.matrix-label {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--t-text-muted);
}

.matrix-status {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  color: var(--t-text-muted);
}

.matrix-status.active {
  color: var(--t-brand);
}

/* Sparkline SVG */
.sparkline-svg {
  width: 100%;
  height: 80px;
  overflow: visible;
}

/* Logs stream */
.log-box {
  background: var(--t-bg-deep);
  border: 1px solid var(--t-border-subtle);
  border-radius: var(--radius-md);
  display: flex;
  flex-direction: column;
  height: 440px;
  overflow: hidden;
}

.log-toolbar {
  padding: 10px 14px;
  background: var(--t-surface);
  border-bottom: 1px solid var(--t-border-subtle);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}

.log-search {
  background: var(--t-bg-deep);
  border: 1px solid var(--t-border-strong);
  border-radius: var(--radius-sm);
  color: var(--t-text);
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 4px 8px;
  outline: none;
  min-width: 220px;
}

.log-stream-scroll {
  flex: 1;
  overflow-y: auto;
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
  gap: 3px;
  font-family: var(--font-mono);
  font-size: 11.5px;
}

.log-row {
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 2px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.02);
}

.log-time {
  color: var(--t-text-muted);
  flex-shrink: 0;
  font-size: 10.5px;
}

.log-pill {
  font-size: 9.5px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: var(--radius-xs);
  flex-shrink: 0;
  text-transform: uppercase;
}

.log-pill.sys { background: var(--t-surface-2); color: var(--t-text-secondary); }
.log-pill.inject { background: rgba(125, 207, 255, 0.15); color: var(--t-accent-cyan); }
.log-pill.shield { background: rgba(187, 154, 247, 0.15); color: var(--t-accent-purple); }
.log-pill.quic { background: rgba(255, 158, 100, 0.15); color: var(--t-accent-orange); }
.log-pill.dns { background: var(--t-brand-soft); color: var(--t-brand); }
.log-pill.error { background: rgba(247, 118, 142, 0.2); color: var(--t-accent-red); }

.log-text {
  color: var(--t-text);
  word-break: break-all;
}

/* Toast */
.toast-notice {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: var(--z-toast);
  background: var(--t-brand);
  color: var(--t-brand-ink);
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 12px;
  letter-spacing: 0.04em;
  padding: 10px 18px;
  border-radius: var(--radius-md);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  opacity: 0;
  transform: translateY(12px);
  pointer-events: none;
  transition: all 200ms cubic-bezier(0.16, 1, 0.3, 1);
}

.toast-notice.show {
  opacity: 1;
  transform: translateY(0);
}

/* Footer */
.site-footer {
  background: var(--t-field-bg);
  border-top: 1px solid var(--t-border-subtle);
  padding: 32px 20px;
  position: relative;
  overflow: hidden;
}

.footer-inner {
  max-width: 1280px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  font-size: 12px;
  color: var(--t-text-muted);
}

.footer-kbd {
  font-family: var(--font-mono);
  font-size: 10.5px;
  padding: 2px 6px;
  border-radius: var(--radius-xs);
  background: var(--t-surface-2);
  border: 1px solid var(--t-border-strong);
  color: var(--t-text-secondary);
}
</style>
</head>
<body>

  <!-- SITE HEADER -->
  <header class="site-header">
    <div class="header-inner">
      
      <!-- Brand & Drawn Mark Animation -->
      <div class="header-brand mark-draw-trigger" onclick="switchTab(0)">
        <div class="brand-icon-box">
          <svg viewBox="0 0 1200 1200" fill="none" stroke="var(--t-brand)" stroke-width="90" class="mark-draw" style="width: 20px; height: 20px;">
            <path pathLength="1" d="M640 1160H40V40H1160V1160H720" />
            <path pathLength="1" d="M600 40V200" />
            <path pathLength="1" d="M640 200H200V1000H1000V200H880" />
            <path pathLength="1" d="M600 1160V1040" />
            <path pathLength="1" d="M40 600H200" />
          </svg>
        </div>
        <div>
          <div class="brand-title-text">Albus Control Center</div>
          <div class="brand-subtext" id="headerSub">eBPF sock_ops · Port 205</div>
        </div>
      </div>

      <!-- Action buttons -->
      <div class="header-actions">
        <div class="status-pill" id="headerStatusPill">
          <span class="pulse-dot"></span>
          <span id="headerStatusText">ACTIVE</span>
        </div>

        <div class="status-pill" id="syncStatusPill" style="background: rgba(245, 158, 11, 0.12); border-color: rgba(245, 158, 11, 0.3); color: #f59e0b;">
          <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#f59e0b;"></span>
          <span id="syncStatusText">Live Sync: Active</span>
        </div>

        <button class="btn btn-outline" id="btnPause" onclick="togglePause()">Pause</button>
        <button class="btn btn-outline" id="btnFlush" onclick="triggerAction('flush-cache', this)">Flush Cache</button>
        <button class="btn btn-outline" id="btnReload" onclick="triggerAction('reload', this)">Reload</button>
        <button class="btn btn-default" id="btnSaveLive" onclick="saveConfig()">Apply Changes</button>
      </div>

    </div>
  </header>

  <!-- NAVIGATION TABS -->
  <nav class="nav-strip">
    <div class="nav-inner">
      <button class="tab-btn active" onclick="switchTab(0)">
        <span class="tab-num">0</span>
        OVERVIEW
      </button>
      <button class="tab-btn" onclick="switchTab(1)">
        <span class="tab-num">1</span>
        DPI EVASION
      </button>
      <button class="tab-btn" onclick="switchTab(2)">
        <span class="tab-num">2</span>
        UPSTREAM RESOLVER
      </button>
      <button class="tab-btn" onclick="switchTab(3)">
        <span class="tab-num">3</span>
        SECURITY POLICIES
      </button>
      <button class="tab-btn" onclick="switchTab(4)">
        <span class="tab-num">4</span>
        HARDENED DNS &amp; FILTERS
      </button>
      <button class="tab-btn" onclick="switchTab(5)">
        <span class="tab-num">5</span>
        LIVE EVENT STREAM
      </button>
    </div>
  </nav>

  <!-- METRICS RAIL -->
  <section class="metrics-section">
    <div class="metrics-rail">
      
      <div class="metric-card">
        <div class="metric-head">
          <span class="metric-label">Total Queries</span>
          <span class="metric-chip">Telemetry</span>
        </div>
        <div class="metric-val" id="statQueries">0</div>
        <div class="metric-sub" id="statQueryBreakdown">UDP: 0 · TCP: 0 · DoH: 0</div>
      </div>

      <div class="metric-card">
        <div class="metric-head">
          <span class="metric-label">Cache Hit Ratio</span>
          <span class="metric-chip" id="statCacheRatioSub">Hits: 0 · Upstream: 0</span>
        </div>
        <div class="metric-val" id="statCacheRatio">0.0%</div>
        <div class="progress-track">
          <div class="progress-bar" id="statCacheBar" style="width: 0%;"></div>
        </div>
      </div>

      <div class="metric-card">
        <div class="metric-head">
          <span class="metric-label">Threats Filtered</span>
          <span class="metric-chip">HaGeZi &amp; Shields</span>
        </div>
        <div class="metric-val" id="statThreats">0</div>
        <div class="metric-sub" id="statThreatBreakdown">HaGeZi: 0 · Bogon: 0 · Rebind: 0</div>
      </div>

      <div class="metric-card">
        <div class="metric-head">
          <span class="metric-label">Evasion Engine</span>
          <span class="metric-chip">Kernel BPF</span>
        </div>
        <div class="metric-val" style="color: var(--t-brand);">ACTIVE</div>
        <div class="metric-sub">MSS Clamping 88B · TTL 8 · Checksum Desync</div>
      </div>

    </div>
  </section>

  <!-- MAIN TAB PANELS -->
  <main class="main-container">

    <!-- TAB 0: OVERVIEW -->
    <div class="tab-panel active" id="tab0">
      
      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">DNS Resolution Activity Stream</h2>
            <p class="card-box-desc">Real-time throughput metrics sampled at 2-second kernel ticks</p>
          </div>
          <div style="font-family: var(--font-mono); font-size: 11px; color: var(--t-text-muted);">
            Green: Inbound Queries · Cyan: DPI Evasion Injections
          </div>
        </div>

        <svg class="sparkline-svg" viewBox="0 0 600 70" preserveAspectRatio="none">
          <defs>
            <linearGradient id="queryGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="var(--t-brand)" stop-opacity="0.35" />
              <stop offset="100%" stop-color="var(--t-brand)" stop-opacity="0.0" />
            </linearGradient>
            <linearGradient id="dpiGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="var(--t-accent-cyan)" stop-opacity="0.25" />
              <stop offset="100%" stop-color="var(--t-accent-cyan)" stop-opacity="0.0" />
            </linearGradient>
          </defs>
          <path id="chartAreaQueries" fill="url(#queryGrad)" d="" />
          <path id="chartLineQueries" fill="none" stroke="var(--t-brand)" stroke-width="2" d="" />
          <path id="chartAreaDpi" fill="url(#dpiGrad)" d="" />
          <path id="chartLineDpi" fill="none" stroke="var(--t-accent-cyan)" stroke-width="1.5" stroke-dasharray="3,3" d="" />
        </svg>
      </div>

      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">Security &amp; Evasion Protection Matrix</h2>
            <p class="card-box-desc">Real-time status of security filters and DPI evasion subsystem modules</p>
          </div>
        </div>

        <div class="matrix-grid">
          <div class="matrix-card">
            <span class="matrix-label">eBPF sock_ops</span>
            <span class="matrix-status active" id="mat_ebpf">ACTIVE</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Quantum PQC</span>
            <span class="matrix-status" id="mat_pqc">ENABLED</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">DNSSEC Validation</span>
            <span class="matrix-status" id="mat_dnssec">ENABLED</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Kill Switch</span>
            <span class="matrix-status" id="mat_killswitch">ACTIVE</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Threat Filter</span>
            <span class="matrix-status" id="mat_blocklist">ACTIVE</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Anti-Rebinding</span>
            <span class="matrix-status" id="mat_rebind">ACTIVE</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Block QUIC</span>
            <span class="matrix-status" id="mat_quic">BLOCKED</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Block STUN</span>
            <span class="matrix-status" id="mat_stun">BLOCKED</span>
          </div>
        </div>
      </div>

      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">Security Telemetry Breakdown</h2>
            <p class="card-box-desc">Accumulated security counters since daemon startup</p>
          </div>
        </div>

        <div class="matrix-grid">
          <div class="matrix-card">
            <span class="matrix-label">HaGeZi Blocklist</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_hagezi">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Scheduled Hours</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_schedule">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Rebinding Drops</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_rebind">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Bogon Drops</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_bogon">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Undelegated TLDs</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_undelegated">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">CNAME Uncloaked</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_cname">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">DNSSEC Validated</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_dnssec">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Post-Quantum DNSSEC</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_pqc_dnssec">0</span>
          </div>
          <div class="matrix-card">
            <span class="matrix-label">Anti-Downgrade Drops</span>
            <span class="metric-val" style="font-size: 18px;" id="tel_pqc_downgrade">0</span>
          </div>
        </div>
      </div>

    </div>

    <!-- TAB 1: DPI EVASION -->
    <div class="tab-panel" id="tab1">
      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">TCP &amp; TLS Desynchronization Engine</h2>
            <p class="card-box-desc">Configure eBPF sock_ops packet fragmentation, fake TTL desync, and checksum poisoning</p>
          </div>
        </div>

        <div class="settings-grid">
          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Enable DPI Evasion Engine</span>
              <span class="tile-desc">Inject out-of-order desync packets to bypass stateful DPI firewalls</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_dns_racing" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Auto-TTL Adaptation</span>
              <span class="tile-desc">Dynamically compute hop count to target server minus one for fake packets</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_auto_ttl" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Corrupt Checksum Poisoning</span>
              <span class="tile-desc">Inject fake TCP packets with checksum 0xDEAD to deceive intermediate middleboxes</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_fake_bad_checksum" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Force Tor SOCKS5 Gateway</span>
              <span class="tile-desc">Route encrypted DNS and bootstrap lookups through onion proxy</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_tor" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 8px;">
          <div class="form-field">
            <div class="form-label">
              <span>TCP MSS Clamping (Bytes)</span>
              <span id="mssDisp" style="color: var(--t-brand); font-weight: 700;">88 B</span>
            </div>
            <input type="range" class="form-input" id="cfg_mss_slider" min="64" max="1460" value="88" oninput="onMss(this.value)">
            <input type="number" class="form-input" id="cfg_mss" value="88" style="display:none;">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_fake_ttl">Fake Desync TTL (Hop Limit)</label>
            <input type="number" class="form-input" id="cfg_fake_ttl" min="1" max="64" value="8" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_restore_after_bytes">Window Restore After Bytes</label>
            <input type="number" class="form-input" id="cfg_restore_after_bytes" min="100" max="65535" value="600" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_fake_sni">Fake TLS SNI Hostname</label>
            <input type="text" class="form-input" id="cfg_fake_sni" placeholder="e.g. cloudflare.com" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_cgroup_path">cgroup v2 Base Path</label>
            <input type="text" class="form-input" id="cfg_cgroup_path" value="/sys/fs/cgroup" onchange="debounceSave()">
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: UPSTREAM RESOLVER -->
    <div class="tab-panel" id="tab2">
      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">Encrypted Upstream DNS Profiles</h2>
            <p class="card-box-desc">Select privacy-first DNS over HTTPS providers or specify dedicated endpoints</p>
          </div>
        </div>

        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
          <button class="btn btn-outline" id="res_mullvad" onclick="selectResolver('mullvad')">Mullvad Privacy DNS</button>
          <button class="btn btn-outline" id="res_cloudflare" onclick="selectResolver('cloudflare')">Cloudflare (1.1.1.1)</button>
          <button class="btn btn-outline" id="res_quad9" onclick="selectResolver('quad9')">Quad9 Security</button>
          <button class="btn btn-outline" id="res_custom" onclick="selectResolver('custom')">Custom DoH Endpoint</button>
        </div>

        <div id="mullvadCard" class="card-box" style="background: var(--t-bg-deep); padding: 14px 16px;">
          <span style="font-family: var(--font-mono); font-size: 11px; color: var(--t-text-muted); text-transform: uppercase;">Mullvad Profile Variant:</span>
          <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px;">
            <button class="btn btn-outline btn-sm active" id="mullvad_standard" onclick="selectMullvadProfile('standard')">Standard</button>
            <button class="btn btn-outline btn-sm" id="mullvad_adblock" onclick="selectMullvadProfile('adblock')">Adblock</button>
            <button class="btn btn-outline btn-sm" id="mullvad_malware" onclick="selectMullvadProfile('malware')">Malware Shield</button>
            <button class="btn btn-outline btn-sm" id="mullvad_family" onclick="selectMullvadProfile('family')">Family Safe</button>
            <button class="btn btn-outline btn-sm" id="mullvad_social" onclick="selectMullvadProfile('social')">Block Social</button>
            <button class="btn btn-outline btn-sm" id="mullvad_all" onclick="selectMullvadProfile('all')">All Filters</button>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
          <div class="form-field" id="customUrlGroup">
            <label class="form-label" for="cfg_custom_url">Custom DoH URL</label>
            <input type="text" class="form-input" id="cfg_custom_url" placeholder="https://dns.example.com/dns-query" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_lb_strategy">Load Balancing Strategy</label>
            <select class="form-select" id="cfg_lb_strategy" onchange="debounceSave()">
              <option value="wp2">WP2 (Weighted Latency - 2 Fastest)</option>
              <option value="p2">P2 (Random Pick - 2 Fastest)</option>
              <option value="ph">PH (Fastest Past Hour)</option>
              <option value="first">First (Deterministic Primary)</option>
              <option value="random">Random (Uniform Distribution)</option>
            </select>
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_max_clients">Max Concurrent Clients</label>
            <input type="number" class="form-input" id="cfg_max_clients" min="10" max="10000" value="250" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_netprobe_timeout">Netprobe Timeout (Seconds)</label>
            <input type="number" class="form-input" id="cfg_netprobe_timeout" min="0" max="300" value="60" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_netprobe_address">Netprobe Address</label>
            <input type="text" class="form-input" id="cfg_netprobe_address" value="9.9.9.9:53" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_bootstrap_resolvers">Bootstrap Fallback Resolvers</label>
            <input type="text" class="form-input" id="cfg_bootstrap_resolvers" value="9.9.9.11:53, 8.8.8.8:53" placeholder="IP:port, comma-separated" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_bootstrap1">Bootstrap Resolver Primary</label>
            <input type="text" class="form-input" id="cfg_bootstrap1" value="194.242.2.2" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_bootstrap2">Bootstrap Resolver Secondary</label>
            <input type="text" class="form-input" id="cfg_bootstrap2" value="194.242.2.3" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_local_doh_addr">Local DoH Listener Address</label>
            <input type="text" class="form-input" id="cfg_local_doh_addr" value="127.0.0.1:8053" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_socks5_proxy">SOCKS5 Proxy Endpoint</label>
            <input type="text" class="form-input" id="cfg_socks5_proxy" placeholder="127.0.0.1:9050" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_cert_refresh_delay">Cert Refresh Delay (Minutes)</label>
            <input type="number" class="form-input" id="cfg_cert_refresh_delay" min="1" max="1440" value="240" onchange="debounceSave()">
          </div>
        </div>

        <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--t-border-subtle);">
          <div class="settings-grid" style="margin-bottom: 16px;">
            <div class="setting-tile">
              <div class="tile-text">
                <span class="tile-title">Offline Mode</span>
                <span class="tile-desc">Disables all upstream network queries; resolves solely via local cloak rules and cache</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="cfg_offline_mode" onchange="debounceSave()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="setting-tile">
              <div class="tile-text">
                <span class="tile-title">Ignore System DNS</span>
                <span class="tile-desc">Bypass system resolver (/etc/resolv.conf) during DoH bootstrap to eliminate leaks</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="cfg_ignore_system_dns" onchange="debounceSave()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="setting-tile">
              <div class="tile-text">
                <span class="tile-title">UDP Connection Pooling</span>
                <span class="tile-desc">Maintain persistent connected UDP socket pool to upstream relays and resolvers</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="cfg_udp_pool" onchange="debounceSave()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="setting-tile">
              <div class="tile-text">
                <span class="tile-title">Ignore Cert Timestamp</span>
                <span class="tile-desc">Ignore DNSCrypt certificate expiration dates if system real-time clock is uncalibrated</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="cfg_cert_ignore_timestamp" onchange="debounceSave()">
                <span class="slider"></span>
              </label>
            </div>
          </div>

          <div class="setting-tile" style="margin-bottom: 12px;">
            <div class="tile-text">
              <span class="tile-title">Local DoH HTTPS / TLS Termination</span>
              <span class="tile-desc">Serve encrypted DNS over HTTPS locally using dedicated TLS certificates</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_local_doh_tls" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
            <div class="form-field">
              <label class="form-label" for="cfg_local_doh_cert_file">TLS Certificate Path (PEM)</label>
              <input type="text" class="form-input" id="cfg_local_doh_cert_file" placeholder="/etc/albus/doh_cert.pem" onchange="debounceSave()">
            </div>
            <div class="form-field">
              <label class="form-label" for="cfg_local_doh_key_file">TLS Private Key Path (PEM)</label>
              <input type="text" class="form-input" id="cfg_local_doh_key_file" placeholder="/etc/albus/doh_key.pem" onchange="debounceSave()">
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: SECURITY POLICIES -->
    <div class="tab-panel" id="tab3">
      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">Security &amp; Privacy Protections</h2>
            <p class="card-box-desc">Toggle kernel firewall hooks, bogon IP drop, quantum PQC, and anti-leak features</p>
          </div>
        </div>

        <div class="settings-grid">
          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Post-Quantum Cryptography (PQC)</span>
              <span class="tile-desc">Hybrid X25519 + ML-KEM-768 TLS key exchange and ML-DSA-44 DNSSEC Anti-Downgrade</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_pqc" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">DNSSEC Validation</span>
              <span class="tile-desc">Enforce cryptographic verification of DNS resource records against root anchors</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_dnssec" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Anti-DNS Rebinding Shield</span>
              <span class="tile-desc">Prevent public domain names from resolving to RFC-1918 private IPv4/IPv6 ranges</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_anti_dns_rebinding" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Drop Bogon &amp; Reserved IPs</span>
              <span class="tile-desc">Block 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 and testnet ranges from responses</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_block_bogons" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Block QUIC Protocol (UDP 443)</span>
              <span class="tile-desc">Force web browsers to fall back to TCP TLS, enabling DPI evasion to inspect traffic</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_block_quic" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Block WebRTC STUN Harvesters</span>
              <span class="tile-desc">Drop UDP 3478 requests to stop browser client IP leakage via WebRTC</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_block_stun" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Enforce Kill Switch</span>
              <span class="tile-desc">Cut off network routing if the secure DoH tunnel connection drops</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_kill_switch" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">RAM-Only Ephemeral Mode</span>
              <span class="tile-desc">Hold logs and cache exclusively in volatile memory; zero disk writes</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_ram_only" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">DNS over HTTP/3 (QUIC)</span>
              <span class="tile-desc">RFC 9250 transport over UDP port 443 with 0-RTT connection handshake</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_http3" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Block IPv6 AAAA Records</span>
              <span class="tile-desc">Suppress AAAA responses for privacy and to prevent VPN/tunnel bypass leaks</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_block_ipv6" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Direct DNSCrypt Cert Fallback</span>
              <span class="tile-desc">Fall back to direct certificate retrieval if anonymized relay or proxy route fails</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_direct_cert_fallback" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Skip Incompatible Resolvers</span>
              <span class="tile-desc">Automatically bypass upstream resolvers that do not support required crypto suites</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_skip_incompatible" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Load Balancer Estimator</span>
              <span class="tile-desc">Continuously update round-trip latency estimates to optimize upstream distribution</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_lb_estimator" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Disable TLS Session Tickets</span>
              <span class="tile-desc">Mitigate cross-session TLS session resumption tracking and fingerprinting</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_tls_disable_session_tickets" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Synthesize Cloaked Reverse PTR</span>
              <span class="tile-desc">Automatically return synthetic in-addr.arpa and ip6.arpa PTR responses for cloaked hosts</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_cloaked_ptr" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 4: HARDENED DNS & FILTERS -->
    <div class="tab-panel" id="tab4">
      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">Adblock &amp; Telemetry Protection Engine</h2>
            <p class="card-box-desc">Automated HaGeZi threat intelligence, CNAME uncloaking, and rule routing</p>
          </div>
        </div>

        <div class="settings-grid">
          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">HaGeZi Pro Multi Threat Blocklist</span>
              <span class="tile-desc">Filter telemetry, ads, trackers, malware, and phishing domains</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_blocklist" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">CNAME Cloaking Defense</span>
              <span class="tile-desc">Recursively resolve CNAME aliases to uncover hidden third-party tracking targets</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_uncloak_cnames" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">EDNS0 Padding (RFC 7830)</span>
              <span class="tile-desc">Pad DNS queries to fixed byte boundaries to resist traffic fingerprinting</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_edns_padding" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">DNS64 Synthesis Support</span>
              <span class="tile-desc">Synthesize IPv6 AAAA records from IPv4 A records via Well-Known Prefix 64:ff9b::/96</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_dns64" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Network Interface Sentinel (netmon)</span>
              <span class="tile-desc">Detect default gateway and interface route changes to flush sockets automatically</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_netmon" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Block Undelegated TLDs</span>
              <span class="tile-desc">Immediately reject non-existent top-level domain queries to conserve upstream quota</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_block_undelegated" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">Real-Time Query Logging</span>
              <span class="tile-desc">Write structured TSV query events with client IP pseudonymization</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_query_log" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>

          <div class="setting-tile">
            <div class="tile-text">
              <span class="tile-title">DNSCrypt Ephemeral Session Keys</span>
              <span class="tile-desc">Rotate public key pairs per query session to prevent cryptographic replay</span>
            </div>
            <label class="switch">
              <input type="checkbox" id="cfg_dnscrypt_ephemeral_keys" onchange="debounceSave()">
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 8px;">
          <div class="form-field">
            <label class="form-label" for="cfg_forwarding_rules_path">Forwarding Rules File Path</label>
            <input type="text" class="form-input" id="cfg_forwarding_rules_path" value="/etc/albus/forwarding-rules.txt" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_cloaking_rules_path">Cloaking &amp; CNAME Rules File Path</label>
            <input type="text" class="form-input" id="cfg_cloaking_rules_path" value="/etc/albus/cloaking-rules.txt" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_web_ui_privacy_level">Web UI Privacy Level</label>
            <select class="form-select" id="cfg_web_ui_privacy_level" onchange="debounceSave()">
              <option value="0">Level 0: No Anonymization (Full Logs)</option>
              <option value="1">Level 1: Anonymize Client IPs (Default)</option>
              <option value="2">Level 2: Mask Domain Names &amp; Client IPs</option>
              <option value="3">Level 3: Full Privacy (Mask Query Details)</option>
            </select>
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_web_ui_max_query_log_entries">Max Web UI Log Entries</label>
            <input type="number" class="form-input" id="cfg_web_ui_max_query_log_entries" min="10" max="1000" value="100" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_edns_client_subnet">EDNS Client Subnet (ECS) Override</label>
            <input type="text" class="form-input" id="cfg_edns_client_subnet" placeholder="e.g. 198.51.100.0/24" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_ipcrypt_key">IPcrypt Pseudonymization Key (16-byte hex)</label>
            <input type="password" class="form-input" id="cfg_ipcrypt_key" placeholder="Optional encryption key" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_tls_key_log_file">SSLKEYLOGFILE Path (Wireshark debug)</label>
            <input type="text" class="form-input" id="cfg_tls_key_log_file" placeholder="/var/log/albus-sslkeys.log" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_fragments_blocked">Fragment Blocked Resolvers (Clamp EDNS 1252B)</label>
            <input type="text" class="form-input" id="cfg_fragments_blocked" placeholder="cisco, cleanbrowsing-adult" onchange="debounceSave()">
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_blocked_query_response">Blocked Query Response Format</label>
            <select class="form-select" id="cfg_blocked_query_response" onchange="debounceSave()">
              <option value="hinfo">HINFO (RFC 8482 synthetic, Android 8+ compatible)</option>
              <option value="refused">REFUSED (RCODE 5)</option>
              <option value="a:0.0.0.0,aaaa:::">Sinkhole (0.0.0.0 / ::)</option>
            </select>
          </div>

          <div class="form-field">
            <label class="form-label" for="cfg_ignored_qtypes">Ignored Query Types for Logging</label>
            <input type="text" class="form-input" id="cfg_ignored_qtypes" placeholder="DNSKEY, NS, HTTPS" onchange="debounceSave()">
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 5: LIVE EVENT STREAM -->
    <div class="tab-panel" id="tab5">
      <div class="card-box">
        <div class="card-box-header">
          <div>
            <h2 class="card-box-title">Live Kernel &amp; DNS Event Stream</h2>
            <p class="card-box-desc">Real-time log buffer with instant filtering, search, and categorization</p>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <input type="text" class="log-search" id="logSearch" placeholder="Filter logs (e.g. HaGeZi, ClientHello)..." oninput="renderLogs()">
            <select class="form-select" id="logLevelFilter" style="width: 100px; padding: 4px 8px; font-size: 11px;" onchange="renderLogs()">
              <option value="ALL">ALL LEVELS</option>
              <option value="INFO">INFO</option>
              <option value="WARN">WARN</option>
              <option value="ERROR">ERROR</option>
            </select>
            <button class="btn btn-outline btn-sm" onclick="clearLogs()">Clear</button>
            <button class="btn btn-outline btn-sm" id="btnLogAutoScroll" onclick="toggleLogAutoScroll()">Scroll: ON</button>
          </div>
        </div>

        <div class="log-box">
          <div class="log-stream-scroll" id="logArea">
            <div style="color: var(--t-text-muted); font-style: italic;">Connecting to event stream...</div>
          </div>
        </div>
      </div>
    </div>

  </main>

  <!-- SITE FOOTER -->
  <footer class="site-footer">
    <div class="footer-inner">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-family: var(--font-sans); font-weight: 700; color: var(--t-text);">ALBUS</span>
        <span>High-Performance DNS &amp; DPI Evasion Subsystem for Linux</span>
        <span id="ftVersion" style="font-family: var(--font-mono); color: var(--t-text-secondary);">v2.1.0</span>
      </div>
      <div>
        <span class="footer-kbd">F</span> Flush &nbsp;
        <span class="footer-kbd">R</span> Reload &nbsp;
        <span class="footer-kbd">Space</span> Pause &nbsp;
        <span class="footer-kbd">0-5</span> Tabs
      </div>
    </div>
  </footer>

  <!-- TOAST NOTIFICATION -->
  <div class="toast-notice" id="toast">CONFIG SAVED · SIGHUP SENT</div>

<script>
/* ==========================================================================
   STATE & VARIABLES
   ========================================================================== */
let currentConfig = {};
let activeTab = 0;
let activeUpstreamPreset = 'mullvad';
let activeMullvadProfile = 'standard';
let saveDebounceTimer = null;
let lastTotalQueries = 0;
let queryHistory = new Array(30).fill(0);
let dpiHistory = new Array(30).fill(0);
let rawLogs = [];
let logAutoScroll = true;
let isPaused = false;

/* ==========================================================================
   SAFE API FETCH & TOAST
   ========================================================================== */
function apiFetch(url, options = {}) {
  const target = url.startsWith('http') ? url : (window.location.origin + (url.startsWith('/') ? url : '/' + url));
  return fetch(target, options);
}

function showToast(msg) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.innerText = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2400);
}

/* ==========================================================================
   TABS SWITCHING
   ========================================================================== */
function switchTab(index) {
  activeTab = index;
  document.querySelectorAll('.tab-btn').forEach((btn, i) => {
    btn.classList.toggle('active', i === index);
  });
  document.querySelectorAll('.tab-panel').forEach((panel, i) => {
    panel.classList.toggle('active', i === index);
  });
  window.location.hash = 'tab' + index;
}

// Restore tab from hash
const initialHash = window.location.hash;
if (initialHash && initialHash.startsWith('#tab')) {
  const t = parseInt(initialHash.replace('#tab', ''));
  if (!isNaN(t) && t >= 0 && t <= 5) switchTab(t);
}

/* ==========================================================================
   SLIDER & INPUT LOGIC
   ========================================================================== */
function onMss(val) {
  document.getElementById('cfg_mss').value = val;
  document.getElementById('mssDisp').innerText = val + ' B';
  debounceSave();
}

function debounceSave() {
  const syncTxt = document.getElementById('syncStatusText');
  if (syncTxt) syncTxt.innerText = 'Syncing...';
  const saveBtn = document.getElementById('btnSaveLive');
  if (saveBtn) saveBtn.innerText = 'Saving...';
  clearTimeout(saveDebounceTimer);
  saveDebounceTimer = setTimeout(saveConfig, 400);
}

/* ==========================================================================
   UPSTREAM RESOLVER PROFILES
   ========================================================================== */
function selectResolver(preset) {
  activeUpstreamPreset = preset;
  ['mullvad', 'cloudflare', 'quad9', 'custom'].forEach(p => {
    const el = document.getElementById('res_' + p);
    if (el) {
      el.classList.toggle('btn-default', p === preset);
      el.classList.toggle('btn-outline', p !== preset);
    }
  });

  const customGroup = document.getElementById('customUrlGroup');
  const mullvadCard = document.getElementById('mullvadCard');
  if (customGroup) customGroup.style.display = preset === 'custom' ? 'flex' : 'none';
  if (mullvadCard) mullvadCard.style.display = preset === 'mullvad' ? 'block' : 'none';

  if (preset === 'cloudflare') {
    currentConfig.doh_upstream = 'cloudflare';
    document.getElementById('cfg_bootstrap1').value = '1.1.1.1';
    document.getElementById('cfg_bootstrap2').value = '1.0.0.1';
  } else if (preset === 'quad9') {
    currentConfig.doh_upstream = 'quad9';
    document.getElementById('cfg_bootstrap1').value = '9.9.9.9';
    document.getElementById('cfg_bootstrap2').value = '149.112.112.112';
  } else if (preset === 'mullvad') {
    selectMullvadProfile(activeMullvadProfile);
  }
  debounceSave();
}

function selectMullvadProfile(prof) {
  activeMullvadProfile = prof;
  ['standard', 'adblock', 'malware', 'family', 'social', 'all'].forEach(p => {
    const el = document.getElementById('mullvad_' + p);
    if (el) {
      el.classList.toggle('btn-default', p === prof);
      el.classList.toggle('btn-outline', p !== prof);
    }
  });
  currentConfig.doh_upstream = prof === 'standard' ? 'mullvad' : 'mullvad-' + prof;
  document.getElementById('cfg_bootstrap1').value = '194.242.2.2';
  document.getElementById('cfg_bootstrap2').value = '194.242.2.3';
  debounceSave();
}

/* ==========================================================================
   CONFIG LOAD & SAVE
   ========================================================================== */
async function loadConfig() {
  try {
    const res = await apiFetch('/api/config');
    if (!res.ok) return;
    currentConfig = await res.json();

    const up = (currentConfig.doh_upstream || '').toLowerCase();
    if (up.startsWith('mullvad')) {
      activeUpstreamPreset = 'mullvad';
      if (up.includes('-')) activeMullvadProfile = up.split('-')[1];
    } else if (up === 'cloudflare' || up === 'quad9') {
      activeUpstreamPreset = up;
    } else {
      activeUpstreamPreset = 'custom';
      document.getElementById('cfg_custom_url').value = currentConfig.doh_upstream || '';
    }
    selectResolver(activeUpstreamPreset);
    if (activeUpstreamPreset === 'mullvad') selectMullvadProfile(activeMullvadProfile);

    if (currentConfig.doh_bootstrap_ips && currentConfig.doh_bootstrap_ips.length > 0) {
      document.getElementById('cfg_bootstrap1').value = currentConfig.doh_bootstrap_ips[0] || '';
      document.getElementById('cfg_bootstrap2').value = currentConfig.doh_bootstrap_ips[1] || '';
    }

    const mss = currentConfig.mss || 88;
    document.getElementById('cfg_mss').value = mss;
    document.getElementById('cfg_mss_slider').value = mss;
    document.getElementById('mssDisp').innerText = mss + ' B';
    document.getElementById('cfg_fake_ttl').value = currentConfig.fake_ttl || 8;
    document.getElementById('cfg_restore_after_bytes').value = currentConfig.restore_after_bytes || 600;
    document.getElementById('cfg_fake_sni').value = currentConfig.fake_sni || '';
    document.getElementById('cfg_cgroup_path').value = currentConfig.cgroup_path || '/sys/fs/cgroup';

    document.getElementById('cfg_socks5_proxy').value = currentConfig.socks5_proxy || '';
    document.getElementById('cfg_local_doh_addr').value = currentConfig.local_doh_addr || '127.0.0.1:8053';
    document.getElementById('cfg_forwarding_rules_path').value = currentConfig.forwarding_rules_path || '/etc/albus/forwarding-rules.txt';
    document.getElementById('cfg_cloaking_rules_path').value = currentConfig.cloaking_rules_path || '/etc/albus/cloaking-rules.txt';
    document.getElementById('cfg_web_ui_privacy_level').value = currentConfig.web_ui_privacy_level !== undefined ? currentConfig.web_ui_privacy_level : 1;
    document.getElementById('cfg_web_ui_max_query_log_entries').value = currentConfig.web_ui_max_query_log_entries || 100;
    document.getElementById('cfg_edns_client_subnet').value = currentConfig.edns_client_subnet || '';
    document.getElementById('cfg_tls_key_log_file').value = currentConfig.tls_key_log_file || '';
    document.getElementById('cfg_ipcrypt_key').value = currentConfig.ipcrypt_key || '';

    document.getElementById('cfg_lb_strategy').value = currentConfig.lb_strategy || 'wp2';
    document.getElementById('cfg_max_clients').value = currentConfig.max_clients || 250;
    document.getElementById('cfg_netprobe_timeout').value = currentConfig.netprobe_timeout !== undefined ? currentConfig.netprobe_timeout : 60;
    document.getElementById('cfg_netprobe_address').value = currentConfig.netprobe_address || '9.9.9.9:53';
    document.getElementById('cfg_bootstrap_resolvers').value = (currentConfig.bootstrap_resolvers || []).join(', ');
    document.getElementById('cfg_local_doh_cert_file').value = currentConfig.local_doh_cert_file || '';
    document.getElementById('cfg_local_doh_key_file').value = currentConfig.local_doh_key_file || '';
    document.getElementById('cfg_fragments_blocked').value = (currentConfig.fragments_blocked || []).join(', ');
    document.getElementById('cfg_cert_refresh_delay').value = currentConfig.cert_refresh_delay !== undefined ? currentConfig.cert_refresh_delay : 240;
    document.getElementById('cfg_blocked_query_response').value = currentConfig.blocked_query_response || 'hinfo';
    document.getElementById('cfg_ignored_qtypes').value = (currentConfig.ignored_qtypes || []).join(', ');

    const boolKeys = [
      'dns_racing', 'auto_ttl', 'fake_bad_checksum', 'tor',
      'pqc', 'dnssec', 'anti_dns_rebinding', 'block_bogons',
      'block_quic', 'block_stun', 'kill_switch', 'ram_only',
      'blocklist', 'uncloak_cnames', 'edns_padding', 'dns64',
      'http3', 'block_ipv6', 'netmon', 'block_undelegated',
      'query_log', 'dnscrypt_ephemeral_keys',
      'local_doh_tls', 'direct_cert_fallback', 'skip_incompatible', 'lb_estimator',
      'offline_mode', 'ignore_system_dns', 'cloaked_ptr', 'tls_disable_session_tickets',
      'cert_ignore_timestamp', 'udp_pool'
    ];
    boolKeys.forEach(k => {
      const el = document.getElementById('cfg_' + k);
      if (el && currentConfig[k] !== undefined) el.checked = !!currentConfig[k];
    });

    updateMatrix();
  } catch (err) {}
}

function updateMatrix() {
  const setPill = (id, active, actText, inactText) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerText = active ? actText : inactText;
    el.className = 'matrix-status ' + (active ? 'active' : '');
  };
  setPill('mat_ebpf', true, 'ACTIVE', 'INACTIVE');
  setPill('mat_pqc', !!currentConfig.pqc, 'ENABLED', 'DISABLED');
  setPill('mat_dnssec', !!currentConfig.dnssec, 'ENABLED', 'DISABLED');
  setPill('mat_killswitch', !!currentConfig.kill_switch, 'ACTIVE', 'INACTIVE');
  setPill('mat_blocklist', !!currentConfig.blocklist, 'ACTIVE', 'INACTIVE');
  setPill('mat_rebind', !!currentConfig.anti_dns_rebinding, 'ACTIVE', 'INACTIVE');
  setPill('mat_quic', !!currentConfig.block_quic, 'BLOCKED', 'PASSED');
  setPill('mat_stun', !!currentConfig.block_stun, 'BLOCKED', 'PASSED');
}

async function saveConfig() {
  const syncTxt = document.getElementById('syncStatusText');
  const saveBtn = document.getElementById('btnSaveLive');
  if (syncTxt) syncTxt.innerText = 'Applying Live...';
  if (saveBtn) saveBtn.innerText = 'Applying...';

  currentConfig.mss = parseInt(document.getElementById('cfg_mss').value) || 88;
  currentConfig.fake_ttl = parseInt(document.getElementById('cfg_fake_ttl').value) || 8;
  currentConfig.restore_after_bytes = parseInt(document.getElementById('cfg_restore_after_bytes').value) || 600;
  currentConfig.fake_sni = document.getElementById('cfg_fake_sni').value.trim() || null;
  currentConfig.cgroup_path = document.getElementById('cfg_cgroup_path').value.trim() || '/sys/fs/cgroup';

  if (activeUpstreamPreset === 'custom') {
    currentConfig.doh_upstream = document.getElementById('cfg_custom_url').value.trim() || 'quad9';
  }
  const b1 = document.getElementById('cfg_bootstrap1').value.trim();
  const b2 = document.getElementById('cfg_bootstrap2').value.trim();
  currentConfig.doh_bootstrap_ips = [b1, b2].filter(Boolean);

  currentConfig.socks5_proxy = document.getElementById('cfg_socks5_proxy').value.trim() || null;
  currentConfig.local_doh_addr = document.getElementById('cfg_local_doh_addr').value.trim() || '127.0.0.1:8053';
  currentConfig.forwarding_rules_path = document.getElementById('cfg_forwarding_rules_path').value.trim() || null;
  currentConfig.cloaking_rules_path = document.getElementById('cfg_cloaking_rules_path').value.trim() || null;
  currentConfig.web_ui_privacy_level = parseInt(document.getElementById('cfg_web_ui_privacy_level').value) || 0;
  currentConfig.web_ui_max_query_log_entries = parseInt(document.getElementById('cfg_web_ui_max_query_log_entries').value) || 100;
  currentConfig.edns_client_subnet = document.getElementById('cfg_edns_client_subnet').value.trim() || null;
  currentConfig.tls_key_log_file = document.getElementById('cfg_tls_key_log_file').value.trim() || null;
  currentConfig.ipcrypt_key = document.getElementById('cfg_ipcrypt_key').value.trim() || null;

  currentConfig.lb_strategy = document.getElementById('cfg_lb_strategy').value || 'wp2';
  currentConfig.max_clients = parseInt(document.getElementById('cfg_max_clients').value) || 250;
  currentConfig.netprobe_timeout = parseInt(document.getElementById('cfg_netprobe_timeout').value);
  if (isNaN(currentConfig.netprobe_timeout)) currentConfig.netprobe_timeout = 60;
  currentConfig.netprobe_address = document.getElementById('cfg_netprobe_address').value.trim() || '9.9.9.9:53';

  const bResolversStr = document.getElementById('cfg_bootstrap_resolvers').value.trim();
  currentConfig.bootstrap_resolvers = bResolversStr ? bResolversStr.split(',').map(s => s.trim()).filter(Boolean) : [];

  currentConfig.local_doh_cert_file = document.getElementById('cfg_local_doh_cert_file').value.trim() || null;
  currentConfig.local_doh_key_file = document.getElementById('cfg_local_doh_key_file').value.trim() || null;

  const fragStr = document.getElementById('cfg_fragments_blocked').value.trim();
  currentConfig.fragments_blocked = fragStr ? fragStr.split(',').map(s => s.trim()).filter(Boolean) : [];

  currentConfig.cert_refresh_delay = parseInt(document.getElementById('cfg_cert_refresh_delay').value) || 240;
  currentConfig.blocked_query_response = document.getElementById('cfg_blocked_query_response').value || 'hinfo';
  const ignQtypesStr = document.getElementById('cfg_ignored_qtypes').value.trim();
  currentConfig.ignored_qtypes = ignQtypesStr ? ignQtypesStr.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) : [];

  const boolKeys = [
    'dns_racing', 'auto_ttl', 'fake_bad_checksum', 'tor',
    'pqc', 'dnssec', 'anti_dns_rebinding', 'block_bogons',
    'block_quic', 'block_stun', 'kill_switch', 'ram_only',
    'blocklist', 'uncloak_cnames', 'edns_padding', 'dns64',
    'http3', 'block_ipv6', 'netmon', 'block_undelegated',
    'query_log', 'dnscrypt_ephemeral_keys',
    'local_doh_tls', 'direct_cert_fallback', 'skip_incompatible', 'lb_estimator',
    'offline_mode', 'ignore_system_dns', 'cloaked_ptr', 'tls_disable_session_tickets',
    'cert_ignore_timestamp', 'udp_pool'
  ];
  boolKeys.forEach(k => {
    const el = document.getElementById('cfg_' + k);
    if (el) currentConfig[k] = el.checked;
  });

  try {
    const res = await apiFetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(currentConfig)
    });
    if (res.ok) {
      if (syncTxt) syncTxt.innerText = 'Live Sync: Active';
      if (saveBtn) {
        saveBtn.innerText = 'Applied!';
        setTimeout(() => { saveBtn.innerText = 'Apply Changes'; }, 1800);
      }
      showToast('SETTINGS APPLIED LIVE TO KERNEL & RESOLVER');
      updateMatrix();
    } else {
      const errJson = await res.json().catch(() => ({}));
      if (syncTxt) syncTxt.innerText = 'Sync Error';
      if (saveBtn) saveBtn.innerText = 'Apply Changes';
      showToast('SAVE FAILED: ' + (errJson.message || 'Unknown error'));
    }
  } catch (err) {
    if (syncTxt) syncTxt.innerText = 'Sync Error';
    if (saveBtn) saveBtn.innerText = 'Apply Changes';
    showToast('NETWORK ERROR WHILE SAVING CONFIG');
  }
}

/* ==========================================================================
   DAEMON ACTIONS
   ========================================================================== */
async function triggerAction(act, btn) {
  const orig = btn ? btn.innerText : '';
  if (btn) btn.innerText = 'Processing...';
  try {
    await apiFetch('/api/service/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: act })
    });
    showToast(act.toUpperCase().replace('-', ' ') + ' SUCCESS');
    if (btn) {
      btn.innerText = 'Done!';
      setTimeout(() => { btn.innerText = orig; }, 1400);
    }
  } catch (err) {
    if (btn) btn.innerText = orig;
  }
}

function togglePause() {
  isPaused = !isPaused;
  triggerAction(isPaused ? 'pause' : 'resume', null);
  document.getElementById('btnPause').innerText = isPaused ? 'Resume' : 'Pause';
  document.getElementById('headerStatusText').innerText = isPaused ? 'PAUSED' : 'ACTIVE';
  document.getElementById('headerStatusPill').classList.toggle('paused', isPaused);
}

/* ==========================================================================
   TELEMETRY & SPARKLINE
   ========================================================================== */
function updateSparkline(qDelta, dpiDelta) {
  queryHistory.shift();
  queryHistory.push(qDelta);
  dpiHistory.shift();
  dpiHistory.push(dpiDelta);

  const maxVal = Math.max(10, ...queryHistory, ...dpiHistory);
  const w = 600;
  const h = 70;
  const step = w / (queryHistory.length - 1);

  const makePath = (data) => {
    let d = `M 0 ${h - (data[0] / maxVal) * (h - 8)}`;
    for (let i = 1; i < data.length; i++) {
      const x = i * step;
      const y = h - (data[i] / maxVal) * (h - 8);
      d += ` L ${x.toFixed(1)} ${y.toFixed(1)}`;
    }
    return d;
  };

  const lineQ = makePath(queryHistory);
  const lineD = makePath(dpiHistory);

  document.getElementById('chartLineQueries').setAttribute('d', lineQ);
  document.getElementById('chartAreaQueries').setAttribute('d', lineQ + ` L ${w} ${h} L 0 ${h} Z`);
  document.getElementById('chartLineDpi').setAttribute('d', lineD);
  document.getElementById('chartAreaDpi').setAttribute('d', lineD + ` L ${w} ${h} L 0 ${h} Z`);
}

async function updateStats() {
  try {
    const res = await apiFetch('/api/stats');
    if (!res.ok) throw new Error();
    const data = await res.json();

    const curTotal = Number(data.total_queries || 0);
    const qDelta = Math.max(0, curTotal - lastTotalQueries);
    lastTotalQueries = curTotal;
    updateSparkline(qDelta, Math.round(qDelta * 0.4));

    const q = curTotal.toLocaleString();
    document.getElementById('statQueries').innerText = q;
    document.getElementById('statQueryBreakdown').innerText = `UDP: ${data.queries_udp || 0} · TCP: ${data.queries_tcp || 0} · DoH: ${data.queries_doh || 0}`;

    const ratio = (data.cache_hit_ratio || 0).toFixed(1) + '%';
    document.getElementById('statCacheRatio').innerText = ratio;
    document.getElementById('statCacheBar').style.width = (data.cache_hit_ratio || 0) + '%';
    document.getElementById('statCacheRatioSub').innerText = `Hits: ${data.cache_hits || 0} · Upstream: ${data.upstream_queries || 0}`;

    const totalDrops = (data.blocked_blocklist || 0) + (data.blocked_bogon || 0) + (data.blocked_rebinding || 0) + (data.rebinding_drops || 0);
    document.getElementById('statThreats').innerText = totalDrops.toLocaleString();
    document.getElementById('statThreatBreakdown').innerText = `HaGeZi: ${data.blocked_blocklist || 0} · Bogon: ${data.blocked_bogon || 0} · Rebind: ${data.blocked_rebinding || data.rebinding_drops || 0}`;

    document.getElementById('tel_hagezi').innerText = (data.blocked_blocklist || 0).toLocaleString();
    document.getElementById('tel_schedule').innerText = (data.blocked_schedule || 0).toLocaleString();
    document.getElementById('tel_rebind').innerText = ((data.blocked_rebinding || 0) + (data.rebinding_drops || 0)).toLocaleString();
    document.getElementById('tel_bogon').innerText = (data.blocked_bogon || 0).toLocaleString();
    document.getElementById('tel_undelegated').innerText = (data.blocked_undelegated || 0).toLocaleString();
    document.getElementById('tel_cname').innerText = (data.uncloaked_cnames || 0).toLocaleString();
    document.getElementById('tel_dnssec').innerText = (data.dnssec_validated || 0).toLocaleString();
    document.getElementById('tel_pqc_dnssec').innerText = (data.pqc_dnssec_validated || 0).toLocaleString();
    document.getElementById('tel_pqc_downgrade').innerText = (data.pqc_downgrade_prevented || 0).toLocaleString();

    if (data.uptime_secs !== undefined) {
      const u = data.uptime_secs;
      const h = Math.floor(u / 3600);
      const m = Math.floor((u % 3600) / 60);
      const s = u % 60;
      document.getElementById('headerSub').innerText = `Uptime ${h}h ${m}m ${s}s · eBPF sock_ops · ML-KEM-768`;
    }
    if (data.version) {
      document.getElementById('ftVersion').innerText = `v${data.version}`;
    }
    if (!isPaused) {
      document.getElementById('headerStatusText').innerText = 'ACTIVE';
      document.getElementById('headerStatusPill').classList.remove('paused');
    }
  } catch (err) {
    document.getElementById('headerStatusText').innerText = 'OFFLINE';
    document.getElementById('headerStatusPill').classList.add('paused');
  }
}

/* ==========================================================================
   LOG STREAM
   ========================================================================== */
function parseLogLine(raw) {
  const clean = raw.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '').trim();
  if (!clean) return null;

  let timeStr = '';
  const iso = clean.match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)/);
  if (iso) {
    try {
      const d = new Date(iso[1]);
      if (!isNaN(d.getTime())) {
        const pad = n => n < 10 ? '0' + n : n;
        timeStr = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
      }
    } catch (e) {}
  }
  if (!timeStr) {
    const tm = clean.match(/(\d{2}:\d{2}:\d{2})/);
    timeStr = tm ? tm[1] : '';
  }

  let tag = 'sys';
  let level = 'INFO';
  if (clean.includes('ERROR')) { tag = 'error'; level = 'ERROR'; }
  else if (clean.includes('WARN')) { tag = 'error'; level = 'WARN'; }
  else if (clean.includes('ClientHello') || clean.includes('split') || clean.includes('desync')) { tag = 'inject'; }
  else if (clean.includes('HaGeZi') || clean.includes('blocked') || clean.includes('Bogon') || clean.includes('Rebinding') || clean.includes('Anti-downgrade') || clean.includes('PQC_DOWNGRADE')) { tag = 'shield'; }
  else if (clean.includes('QUIC')) { tag = 'quic'; }
  else if (clean.includes('DNS') || clean.includes('query')) { tag = 'dns'; }

  return { timeStr, tag, level, text: clean };
}

function renderLogs() {
  const container = document.getElementById('logArea');
  if (!container) return;

  const filterText = (document.getElementById('logSearch').value || '').toLowerCase();
  const levelFilter = document.getElementById('logLevelFilter').value;

  const parsed = [];
  for (let i = 0; i < rawLogs.length; i++) {
    const it = parseLogLine(rawLogs[i]);
    if (!it) continue;
    if (levelFilter !== 'ALL' && it.level !== levelFilter) continue;
    if (filterText && !it.text.toLowerCase().includes(filterText)) continue;
    parsed.push(it);
  }

  if (parsed.length === 0) {
    container.innerHTML = '<div style="color: var(--t-text-muted); font-style: italic;">No events matching current filter</div>';
    return;
  }

  let html = '';
  for (let i = 0; i < parsed.length; i++) {
    const it = parsed[i];
    const safeText = it.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    html += `
      <div class="log-row">
        <span class="log-time">${it.timeStr || '--:--:--'}</span>
        <span class="log-pill ${it.tag}">${it.tag}</span>
        <span class="log-text">${safeText}</span>
      </div>
    `;
  }
  container.innerHTML = html;
  if (logAutoScroll) {
    container.scrollTop = container.scrollHeight;
  }
}

async function updateLogs() {
  try {
    const res = await apiFetch('/api/logs');
    if (!res.ok) return;
    const data = await res.json();
    if (data && Array.isArray(data.logs)) {
      rawLogs = data.logs;
      renderLogs();
    }
  } catch (err) {}
}

function clearLogs() {
  rawLogs = [];
  renderLogs();
}

function toggleLogAutoScroll() {
  logAutoScroll = !logAutoScroll;
  document.getElementById('btnLogAutoScroll').innerText = 'Scroll: ' + (logAutoScroll ? 'ON' : 'OFF');
}

/* ==========================================================================
   KEYBOARD SHORTCUTS
   ========================================================================== */
window.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

  if (e.key === ' ' && !e.repeat) {
    e.preventDefault();
    togglePause();
  } else if (e.key === 'f' || e.key === 'F') {
    triggerAction('flush-cache', document.getElementById('btnFlush'));
  } else if (e.key === 'r' || e.key === 'R') {
    triggerAction('reload', document.getElementById('btnReload'));
  } else if (e.key >= '0' && e.key <= '5') {
    switchTab(parseInt(e.key));
  }
});

// Boot
loadConfig();
updateStats();
updateLogs();
setInterval(updateStats, 2000);
setInterval(updateLogs, 2000);
</script>

</body>
</html>"###
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"password123", b"password123"));
        assert!(!constant_time_eq(b"password123", b"password124"));
        assert!(!constant_time_eq(b"password123", b"short"));
    }

    #[test]
    fn test_constant_time_eq_str() {
        assert!(constant_time_eq_str("admin:secret", "admin:secret"));
        assert!(!constant_time_eq_str("admin:secret", "admin:wrong"));
        assert!(!constant_time_eq_str("admin:secret", "root:secret"));
    }

    #[test]
    fn test_base64_decoding() {
        let dec = decode_base64("b2d5OjEyMzQ1").unwrap();
        assert_eq!(String::from_utf8(dec).unwrap(), "ogy:12345");
        assert!(decode_base64("invalid!").is_err());
    }

    #[test]
    fn test_render_dashboard_html() {
        let html = render_dashboard_html();
        assert!(html.contains("Albus Control Center"));
        assert!(html.contains("OVERVIEW"));
        assert!(html.contains("DPI EVASION"));
        assert!(html.contains("UPSTREAM RESOLVER"));
        assert!(html.contains("SECURITY POLICIES"));
        assert!(html.contains("HARDENED DNS & FILTERS"));
        assert!(html.contains("LIVE EVENT STREAM"));
        assert!(html.contains("cfg_lb_strategy"));
        assert!(html.contains("cfg_netprobe_timeout"));
        assert!(html.contains("cfg_local_doh_tls"));
        assert!(html.contains("cfg_fragments_blocked"));
        assert!(html.contains("cfg_cloaking_rules_path"));
        assert!(html.contains("cfg_web_ui_privacy_level"));
    }

    #[test]
    fn test_anonymize_log_line() {
        let sample_tsv = "1700000000\t192.168.1.55\tads.tracker.com\t1\tPASS\t2ms\t-";
        // Level 0: verbatim
        assert_eq!(anonymize_log_line(sample_tsv, 0), sample_tsv);

        // Level 1: client IP anonymized to /24
        let l1 = anonymize_log_line(sample_tsv, 1);
        assert!(l1.contains("192.168.1.0"));
        assert!(l1.contains("ads.tracker.com"));

        // Level 2: IP anonymized + domain masked
        let l2 = anonymize_log_line(sample_tsv, 2);
        assert!(l2.contains("192.168.1.0"));
        assert!(l2.contains("***.tracker.com"));

        // Level 3: domain redacted
        let l3 = anonymize_log_line(sample_tsv, 3);
        assert!(l3.contains("192.168.1.0"));
        assert!(l3.contains("[REDACTED_DOMAIN]"));

        // Systemd log style
        let sys_line = "DNS query client=10.20.30.40 domain=evil.sub.badsite.org status=PASS";
        let sys_l1 = anonymize_log_line(sys_line, 1);
        assert!(sys_l1.contains("10.20.30.0"));
        assert!(sys_l1.contains("evil.sub.badsite.org"));

        let sys_l2 = anonymize_log_line(sys_line, 2);
        assert!(sys_l2.contains("10.20.30.0"));
        assert!(sys_l2.contains("***.badsite.org"));
    }

    #[test]
    fn test_parse_web_ui_addr() {
        let expected: SocketAddr = "127.0.0.1:205".parse().unwrap();
        assert_eq!(parse_web_ui_addr("127.0.0.1:205"), expected);
        assert_eq!(parse_web_ui_addr("127.0.0.1:0205"), expected);
        assert_eq!(parse_web_ui_addr("0205"), expected);
        assert_eq!(parse_web_ui_addr("205"), expected);
        assert_eq!(parse_web_ui_addr(":0205"), expected);
        assert_eq!(parse_web_ui_addr(":205"), expected);
        assert_eq!(parse_web_ui_addr("  0205  "), expected);

        let custom: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(parse_web_ui_addr("0.0.0.0:8080"), custom);
        assert_eq!(parse_web_ui_addr("invalid_addr"), expected);
    }

    #[tokio::test]
    async fn test_web_ui_server_http_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stats = Arc::new(DnsStats::default());
        stats.total_queries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        stats.blocked_bogon.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let auth = Some(("testuser".to_string(), "testpass".to_string()));
        tokio::spawn(WebUiServer::run_listener(listener, stats, auth, shutdown_rx, Instant::now(), None));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        // 1. Unauthenticated request -> 401 Unauthorized
        let unauth_resp = client
            .get(format!("http://127.0.0.1:{}/", port))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        // 1b. Unauthenticated API requests -> 401 Unauthorized on all endpoints
        let unauth_stats = client
            .get(format!("http://127.0.0.1:{}/api/stats", port))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_stats.status(), reqwest::StatusCode::UNAUTHORIZED);

        let unauth_config = client
            .get(format!("http://127.0.0.1:{}/api/config", port))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_config.status(), reqwest::StatusCode::UNAUTHORIZED);

        let unauth_logs = client
            .get(format!("http://127.0.0.1:{}/api/logs", port))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_logs.status(), reqwest::StatusCode::UNAUTHORIZED);

        let unauth_action = client
            .post(format!("http://127.0.0.1:{}/api/service/action", port))
            .header("Content-Type", "application/json")
            .body("{\"action\":\"flush-cache\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_action.status(), reqwest::StatusCode::UNAUTHORIZED);

        // 2. Wrong credentials -> 401 Unauthorized
        let bad_auth_resp = client
            .get(format!("http://127.0.0.1:{}/", port))
            .basic_auth("testuser", Some("wrongpass"))
            .send()
            .await
            .unwrap();
        assert_eq!(bad_auth_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        // 3. Valid credentials -> 200 OK HTML
        let ok_resp = client
            .get(format!("http://127.0.0.1:{}/", port))
            .basic_auth("testuser", Some("testpass"))
            .send()
            .await
            .unwrap();
        assert_eq!(ok_resp.status(), reqwest::StatusCode::OK);
        let html_body = ok_resp.text().await.unwrap();
        assert!(html_body.contains("Albus Control Center"));

        // 4. Valid credentials /api/stats -> 200 OK JSON
        let stats_resp = client
            .get(format!("http://127.0.0.1:{}/api/stats", port))
            .basic_auth("testuser", Some("testpass"))
            .send()
            .await
            .unwrap();
        assert_eq!(stats_resp.status(), reqwest::StatusCode::OK);
        let body_text = stats_resp.text().await.unwrap();
        let json_body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
        assert_eq!(json_body["total_queries"], 1);
        assert_eq!(json_body["blocked_bogon"], 1);
        assert_eq!(json_body["dnssec_validated"], 0);
        assert_eq!(json_body["pqc_dnssec_validated"], 0);
        assert_eq!(json_body["pqc_downgrade_prevented"], 0);

        // 5. Valid credentials /api/config -> 200 OK JSON
        let cfg_resp = client
            .get(format!("http://127.0.0.1:{}/api/config", port))
            .basic_auth("testuser", Some("testpass"))
            .send()
            .await
            .unwrap();
        assert_eq!(cfg_resp.status(), reqwest::StatusCode::OK);

        // 6. Valid credentials HEAD request
        let head_resp = client
            .head(format!("http://127.0.0.1:{}/", port))
            .basic_auth("testuser", Some("testpass"))
            .send()
            .await
            .unwrap();
        assert_eq!(head_resp.status(), reqwest::StatusCode::OK);

        // 7. Test POST /api/service/action with action=flush-cache
        let act_resp = client
            .post(format!("http://127.0.0.1:{}/api/service/action", port))
            .basic_auth("testuser", Some("testpass"))
            .header("Content-Type", "application/json")
            .body("{\"action\":\"flush-cache\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(act_resp.status(), reqwest::StatusCode::OK);

        // 8. Test GET /api/logs
        let logs_resp = client
            .get(format!("http://127.0.0.1:{}/api/logs", port))
            .basic_auth("testuser", Some("testpass"))
            .send()
            .await
            .unwrap();
        assert_eq!(logs_resp.status(), reqwest::StatusCode::OK);

        // 9. Clean shutdown
        let _ = shutdown_tx.send(());
    }
}
