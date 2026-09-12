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
            } else if k == "domain" || k == "qname" || k == "host" {
                target.push_str(k);
                target.push('=');
                if privacy_level >= 2 {
                    target.push_str(&anonymize_token(v));
                } else {
                    target.push_str(v);
                }
            } else {
                target.push_str(k);
                target.push('=');
                target.push_str(v);
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
    include_str!("dashboard.html").to_string()
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
