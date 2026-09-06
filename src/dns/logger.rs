//! structured query and threat audit logger with rotation and ip pseudonymization.
//!
//! records timestamped dns transactions (client ip, qname, qtype, decision status, latency)
//! into rotating tsv/json log files via non-blocking asynchronous queue channels.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

use super::ipcrypt::IpCrypt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStatus {
    Pass,
    BlockHagezi,
    UncloakedCname,
    RebindRefused,
    BogonDrop,
    Cloak0ms,
    CacheHit,
    Canary,
    Captive,
    Undelegated,
    NxDomain,
}

impl QueryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::BlockHagezi => "BLOCK_HAGEZI",
            Self::UncloakedCname => "UNCLOAKED_CNAME",
            Self::RebindRefused => "REBIND_REFUSED",
            Self::BogonDrop => "BOGON_DROP",
            Self::Cloak0ms => "CLOAK_0MS",
            Self::CacheHit => "CACHE_HIT",
            Self::Canary => "CANARY",
            Self::Captive => "CAPTIVE",
            Self::Undelegated => "UNDELEGATED",
            Self::NxDomain => "NXDOMAIN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueryLogEntry {
    pub timestamp_epoch_secs: u64,
    pub client_ip: IpAddr,
    pub domain: String,
    pub qtype: u16,
    pub status: QueryStatus,
    pub duration_ms: u32,
    pub details: Option<String>,
}

struct LogFileState {
    path: PathBuf,
    file: Option<File>,
    current_size: u64,
    max_bytes: u64,
    max_backups: usize,
}

impl LogFileState {
    fn new(path: PathBuf, max_bytes: u64, max_backups: usize) -> Self {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }

        let file = match options.open(&path) {
            Ok(f) => Some(f),
            Err(e) => {
                warn!("failed to open audit log file {}: {}", path.display(), e);
                None
            }
        };

        let current_size = file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map(|m| m.len())
            .unwrap_or(0);

        Self {
            path,
            file,
            current_size,
            max_bytes,
            max_backups,
        }
    }

    fn write_line(&mut self, line: &str) {
        let line_len = line.len() as u64;
        if self.current_size + line_len > self.max_bytes {
            drop(self.file.take());
            rotate_files(&self.path, self.max_backups);
            let mut rot_opt = OpenOptions::new();
            rot_opt.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                rot_opt
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            self.file = rot_opt.open(&self.path).ok();
            self.current_size = 0;
        }

        if let Some(ref mut f) = self.file {
            if let Ok(()) = f.write_all(line.as_bytes()) {
                let _ = f.flush();
                self.current_size += line_len;
            }
        }
    }
}

pub struct QueryLogger {
    tx: mpsc::Sender<QueryLogEntry>,
}

impl QueryLogger {
    // spawns background non-blocking disk writer with optional main log and dedicated nxdomain audit log
    pub fn start<P1: AsRef<Path>, P2: AsRef<Path>>(
        main_path: Option<P1>,
        nx_path: Option<P2>,
        ip_crypt: Option<Arc<IpCrypt>>,
        max_bytes: u64,
        max_backups: usize,
    ) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<QueryLogEntry>(2048);
        let main_path_buf = main_path.map(|p| p.as_ref().to_path_buf());
        let nx_path_buf = nx_path.map(|p| p.as_ref().to_path_buf());

        tokio::spawn(async move {
            let mut main_state =
                main_path_buf.map(|p| LogFileState::new(p, max_bytes, max_backups));
            let mut nx_state = nx_path_buf.map(|p| LogFileState::new(p, max_bytes, max_backups));

            while let Some(entry) = rx.recv().await {
                let client_display = match entry.client_ip {
                    IpAddr::V4(v4) => {
                        if let Some(ref crypt) = ip_crypt {
                            format!("ip:{}", crypt.encrypt(v4))
                        } else {
                            v4.to_string()
                        }
                    }
                    IpAddr::V6(v6) => {
                        if ip_crypt.is_some() {
                            // mask host bits of ipv6 for privacy
                            let segs = v6.segments();
                            format!(
                                "{:x}:{:x}:{:x}:{:x}::[masked]",
                                segs[0], segs[1], segs[2], segs[3]
                            )
                        } else {
                            v6.to_string()
                        }
                    }
                };

                let safe_domain = sanitize_log_field(&entry.domain);
                let safe_details =
                    sanitize_log_field(&entry.details.unwrap_or_else(|| "-".to_string()));

                let line = format!(
                    "{}\t{}\t{}\t{}\t{}\t{}ms\t{}\n",
                    entry.timestamp_epoch_secs,
                    client_display,
                    safe_domain,
                    entry.qtype,
                    entry.status.as_str(),
                    entry.duration_ms,
                    safe_details
                );

                if let Some(ref mut main) = main_state {
                    main.write_line(&line);
                }

                if entry.status == QueryStatus::NxDomain {
                    if let Some(ref mut nx) = nx_state {
                        nx.write_line(&line);
                    }
                }
            }
        });

        Arc::new(Self { tx })
    }

    // convenience constructor for single destination logging
    pub fn start_single<P: AsRef<Path>>(
        path: P,
        ip_crypt: Option<Arc<IpCrypt>>,
        max_bytes: u64,
        max_backups: usize,
    ) -> Arc<Self> {
        Self::start(
            Some(path),
            None::<PathBuf>,
            ip_crypt,
            max_bytes,
            max_backups,
        )
    }

    pub fn log(&self, entry: QueryLogEntry) {
        let _ = self.tx.try_send(entry);
    }
}

// sanitizes log fields by neutralizing control characters, newlines, and tabs
fn sanitize_log_field(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\t' => ' ',
            '\n' | '\r' => '?',
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

// rotates file.log -> file.log.1 -> file.log.2
fn rotate_files(base_path: &Path, max_backups: usize) {
    if max_backups == 0 {
        let _ = fs::remove_file(base_path);
        return;
    }
    for i in (1..max_backups).rev() {
        let src = format!("{}.{}", base_path.display(), i);
        let dst = format!("{}.{}", base_path.display(), i + 1);
        if Path::new(&src).exists() {
            let _ = fs::rename(&src, &dst);
        }
    }
    let first = format!("{}.1", base_path.display());
    let _ = fs::rename(base_path, &first);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_log_status_string() {
        assert_eq!(QueryStatus::Pass.as_str(), "PASS");
        assert_eq!(QueryStatus::BlockHagezi.as_str(), "BLOCK_HAGEZI");
        assert_eq!(QueryStatus::UncloakedCname.as_str(), "UNCLOAKED_CNAME");
    }

    #[test]
    fn test_query_logger_field_sanitization() {
        let malicious = "evil.com\n1700000000\tip:10.0.0.1\tinjected\r\n";
        let sanitized = sanitize_log_field(malicious);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\t'));
        assert_eq!(sanitized, "evil.com?1700000000 ip:10.0.0.1 injected??");
    }

    #[tokio::test]
    async fn test_query_logger_file_write_and_ipcrypt() {
        let temp_dir = std::env::temp_dir().join(format!("albus_log_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let log_file = temp_dir.join("query.log");

        let ip_crypt = Some(Arc::new(IpCrypt::from_passphrase("test-secret-key")));
        let logger = QueryLogger::start_single(&log_file, ip_crypt, 1024, 2);

        logger.log(QueryLogEntry {
            timestamp_epoch_secs: 1700000000,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            domain: "tracker.ad.com\nmalicious.com".to_string(),
            qtype: 1,
            status: QueryStatus::BlockHagezi,
            duration_ms: 2,
            details: Some("hagezi\trule".to_string()),
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let content = fs::read_to_string(&log_file).expect("log file should exist");
        assert!(content.contains("tracker.ad.com?malicious.com"));
        assert!(content.contains("hagezi rule"));
        assert_eq!(
            content.lines().count(),
            1,
            "Log injection attempt MUST NOT create extra lines"
        );
        assert!(content.contains("BLOCK_HAGEZI"));
        assert!(content.contains("ip:")); // pseudonymized with ip: prefix

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_nx_log_generation() {
        let temp_dir =
            std::env::temp_dir().join(format!("albus_nx_log_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let query_file = temp_dir.join("query.log");
        let nx_file = temp_dir.join("nx.log");

        let logger = QueryLogger::start(Some(&query_file), Some(&nx_file), None, 1024, 2);

        // 1. send regular pass query
        logger.log(QueryLogEntry {
            timestamp_epoch_secs: 1700000001,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            domain: "google.com".to_string(),
            qtype: 1,
            status: QueryStatus::Pass,
            duration_ms: 5,
            details: Some("quad9".to_string()),
        });

        // 2. send nxdomain query (e.g. dga malware query)
        logger.log(QueryLogEntry {
            timestamp_epoch_secs: 1700000002,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            domain: "dga12345nonexistent.biz".to_string(),
            qtype: 1,
            status: QueryStatus::NxDomain,
            duration_ms: 12,
            details: Some("quad9".to_string()),
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let query_content = fs::read_to_string(&query_file).expect("query log must exist");
        assert!(query_content.contains("google.com"));
        assert!(query_content.contains("dga12345nonexistent.biz"));

        let nx_content = fs::read_to_string(&nx_file).expect("nx log must exist");
        // nx.log must ONLY contain the NXDomain query
        assert!(!nx_content.contains("google.com"));
        assert!(nx_content.contains("dga12345nonexistent.biz"));
        assert!(nx_content.contains("NXDOMAIN"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
