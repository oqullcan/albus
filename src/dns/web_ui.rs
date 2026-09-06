//! lightweight embedded web monitoring dashboard (http://127.0.0.1:205) for albus.
//!
//! provides a zero-external-dependency, real-time web interface for inspecting
//! dns query statistics, cache performance, blocking actions, and latency telemetry.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, info, warn};

use super::stats::DnsStats;

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

pub struct WebUiServer;

const MAX_CONCURRENT_WEB_CONNS: usize = 32;
const MAX_REQUEST_SIZE: usize = 4096;

impl WebUiServer {
    pub fn start(
        bind_addr: SocketAddr,
        stats: Arc<DnsStats>,
        auth: Option<(String, String)>,
        shutdown_rx: broadcast::Receiver<()>,
    ) {
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

            Self::run_listener(listener, stats, auth, shutdown_rx).await;
        });
    }

    pub async fn run_listener(
        listener: TcpListener,
        stats: Arc<DnsStats>,
        auth: Option<(String, String)>,
        mut shutdown_rx: broadcast::Receiver<()>,
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

                            tokio::spawn(async move {
                                let _permit = permit;
                                let mut buf = [0u8; MAX_REQUEST_SIZE];

                                let read_res = tokio::time::timeout(
                                    Duration::from_secs(3),
                                    stream.read(&mut buf),
                                )
                                .await;

                                let n = match read_res {
                                    Ok(Ok(n)) if n > 0 => n,
                                    _ => return,
                                };

                                let req_str = String::from_utf8_lossy(&buf[..n]);
                                let first_line = req_str.lines().next().unwrap_or("");
                                let parts: Vec<&str> = first_line.split_whitespace().collect();

                                if parts.len() < 2 {
                                    return;
                                }

                                let method = parts[0];
                                let path = parts[1];

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

                                let response = match (method, path) {
                                    ("GET", "/") | ("GET", "/index.html") => {
                                        let html = render_dashboard_html();
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            html.len(),
                                            html
                                        )
                                    }
                                    ("GET", "/api/stats") => {
                                        let snap = stats_clone.snapshot();
                                        let json = serde_json::to_string(&snap).unwrap_or_else(|_| "{}".to_string());
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            json.len(),
                                            json
                                        )
                                    }
                                    ("GET", "/api/health") | ("GET", "/live") => {
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_string()
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
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Albus DNS Monitor</title>
<style>
:root {
  --bg: #0d1117;
  --card: #161b22;
  --border: #30363d;
  --cyan: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --purple: #bc8cff;
  --text: #c9d1d9;
  --muted: #8b949e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background-color: var(--bg);
  color: var(--text);
  padding: 24px;
  line-height: 1.5;
}
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 24px;
}
.title-group { display: flex; align-items: center; gap: 12px; }
h1 { font-size: 20px; font-weight: 600; color: #f0f6fc; letter-spacing: 0.5px; }
.badge {
  background: rgba(63, 185, 80, 0.15);
  color: var(--green);
  border: 1px solid rgba(63, 185, 80, 0.4);
  padding: 3px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  display: flex;
  flex-direction: column;
}
.card-label { font-size: 12px; color: var(--muted); font-weight: 500; margin-bottom: 6px; }
.card-val { font-size: 26px; font-weight: 700; color: #f0f6fc; font-family: monospace; }
.card-sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
.val-cyan { color: var(--cyan); }
.val-green { color: var(--green); }
.val-red { color: var(--red); }
.val-purple { color: var(--purple); }
.section-title { font-size: 14px; font-weight: 600; color: #f0f6fc; margin-bottom: 12px; }
.table-container {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 24px;
}
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 10px 16px; text-align: left; }
th { background: rgba(255, 255, 255, 0.03); color: var(--muted); font-weight: 600; border-bottom: 1px solid var(--border); }
tr:not(:last-child) td { border-bottom: 1px solid var(--border); }
.num-cell { text-align: right; font-family: monospace; font-weight: 600; }
.footer { font-size: 11px; color: var(--muted); text-align: center; margin-top: 32px; }
</style>
</head>
<body>
<div class="header">
  <div class="title-group">
    <h1>Albus DNS Telemetry</h1>
    <span class="badge" id="statusBadge">LIVE</span>
  </div>
  <div style="font-size: 12px; color: var(--muted);" id="lastUpdated">Updating...</div>
</div>

<div class="grid">
  <div class="card">
    <div class="card-label">TOTAL QUERIES</div>
    <div class="card-val val-cyan" id="totalQueries">0</div>
    <div class="card-sub" id="queryBreakdown">UDP: 0 | TCP: 0 | DoH: 0</div>
  </div>
  <div class="card">
    <div class="card-label">CACHE HITS</div>
    <div class="card-val val-green" id="cacheHits">0</div>
    <div class="card-sub" id="cacheRatio">Hit Ratio: 0.0%</div>
  </div>
  <div class="card">
    <div class="card-label">BLOCKED DOMAINS</div>
    <div class="card-val val-red" id="blockedDomains">0</div>
    <div class="card-sub" id="blockedBreakdown">Blocklist: 0 | Sched: 0</div>
  </div>
  <div class="card">
    <div class="card-label">ACTIVE CONCURRENCY</div>
    <div class="card-val val-purple" id="activeQueries">0</div>
    <div class="card-sub">In-flight Queries</div>
  </div>
</div>

<div class="section-title">Security & Drop Telemetry</div>
<div class="table-container">
  <table>
    <thead>
      <tr>
        <th>Protection Mechanism</th>
        <th>Category / Reason</th>
        <th class="num-cell">Total Drops</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Domain Blocklist</td>
        <td>Ad / Tracking / Malware Feeds (HaGeZi Arena)</td>
        <td class="num-cell" id="statBlocklist">0</td>
      </tr>
      <tr>
        <td>Time Schedules</td>
        <td>Parental / Night-time Scheduled Enforcements</td>
        <td class="num-cell" id="statSchedule">0</td>
      </tr>
      <tr>
        <td>Anti-DNS Rebinding</td>
        <td>Private IP Injection Protection (RFC 1918)</td>
        <td class="num-cell" id="statRebinding">0</td>
      </tr>
      <tr>
        <td>Bogon Filtering</td>
        <td>Unallocated / Reserved Routing Blocks</td>
        <td class="num-cell" id="statBogon">0</td>
      </tr>
      <tr>
        <td>Undelegated Zones</td>
        <td>Dotless Hostnames & Internal Leakage Protection</td>
        <td class="num-cell" id="statUndelegated">0</td>
      </tr>
      <tr>
        <td>Uncloaked CNAMEs</td>
        <td>Deep Tracker Alias Discovery</td>
        <td class="num-cell" id="statUncloaked">0</td>
      </tr>
    </tbody>
  </table>
</div>

<div class="footer">Albus eBPF + Hardened DNS Server &bull; Zero Leaks &bull; Pure Rust</div>

<script>
async function updateStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) throw new Error('status ' + res.status);
    const data = await res.json();
    document.getElementById('totalQueries').innerText = Number(data.total_queries || 0).toLocaleString();
    document.getElementById('queryBreakdown').innerText = `UDP: ${data.queries_udp || 0} | TCP: ${data.queries_tcp || 0} | DoH: ${data.queries_doh || 0}`;
    document.getElementById('cacheHits').innerText = Number(data.cache_hits || 0).toLocaleString();
    document.getElementById('cacheRatio').innerText = `Hit Ratio: ${(data.cache_hit_ratio || 0).toFixed(1)}%`;
    document.getElementById('blockedDomains').innerText = Number(data.blocked_domains || 0).toLocaleString();
    document.getElementById('blockedBreakdown').innerText = `Blocklist: ${data.blocked_blocklist || 0} | Sched: ${data.blocked_schedule || 0}`;
    document.getElementById('activeQueries').innerText = Number(data.active_queries || 0).toLocaleString();
    document.getElementById('statBlocklist').innerText = Number(data.blocked_blocklist || 0).toLocaleString();
    document.getElementById('statSchedule').innerText = Number(data.blocked_schedule || 0).toLocaleString();
    document.getElementById('statRebinding').innerText = Number(data.blocked_rebinding || 0).toLocaleString();
    document.getElementById('statBogon').innerText = Number(data.blocked_bogon || 0).toLocaleString();
    document.getElementById('statUndelegated').innerText = Number(data.blocked_undelegated || 0).toLocaleString();
    document.getElementById('statUncloaked').innerText = Number(data.uncloaked_cnames || 0).toLocaleString();
    document.getElementById('lastUpdated').innerText = 'Last updated: ' + new Date().toLocaleTimeString();
  } catch (err) {
    document.getElementById('lastUpdated').innerText = 'Connection paused';
  }
}
updateStats();
setInterval(updateStats, 2000);
</script>
</body>
</html>"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decoding() {
        let decoded = decode_base64("YWxidXM6c2VjcmV0").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "albus:secret");

        let decoded2 = decode_base64("YWRtaW46YWRtaW4=").unwrap();
        assert_eq!(String::from_utf8(decoded2).unwrap(), "admin:admin");
    }

    #[test]
    fn test_render_dashboard_html() {
        let html = render_dashboard_html();
        assert!(html.contains("Albus DNS Telemetry"));
        assert!(html.contains("/api/stats"));
        assert!(html.contains("TOTAL QUERIES"));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"password123", b"password123"));
        assert!(!constant_time_eq(b"password123", b"password124"));
        assert!(!constant_time_eq(b"short", b"longer_password"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_constant_time_eq_str() {
        assert!(constant_time_eq_str("admin", "admin"));
        assert!(constant_time_eq_str(
            "supersecretpassword",
            "supersecretpassword"
        ));
        assert!(!constant_time_eq_str("admin", "root"));
        assert!(!constant_time_eq_str("password123", "password124"));
        assert!(!constant_time_eq_str("", "admin"));
    }

    #[tokio::test]
    async fn test_web_ui_server_http_end_to_end() {
        use std::sync::atomic::Ordering;
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let stats = DnsStats::new();
        stats.total_queries.fetch_add(1, Ordering::Relaxed);
        stats.blocked_bogon.fetch_add(1, Ordering::Relaxed);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let auth = Some(("testuser".to_string(), "testpass".to_string()));
        tokio::spawn(WebUiServer::run_listener(listener, stats, auth, shutdown_rx));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();

        // 1. Unauthenticated request -> 401 Unauthorized
        let unauth_resp = client
            .get(format!("http://127.0.0.1:{}/", port))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

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
        assert!(html_body.contains("Albus DNS Telemetry"));

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

        // 5. Clean shutdown
        let _ = shutdown_tx.send(());
    }
}
