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

#[derive(Debug, Clone)]
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

pub struct QueryLogger {
    tx: mpsc::Sender<QueryLogEntry>,
}

impl QueryLogger {
    // spawns background non-blocking disk writer with file size rotation
    pub fn start<P: AsRef<Path>>(
        path: P,
        ip_crypt: Option<Arc<IpCrypt>>,
        max_bytes: u64,
        max_backups: usize,
    ) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<QueryLogEntry>(2048);
        let log_path = path.as_ref().to_path_buf();

        if let Some(parent) = log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        tokio::spawn(async move {
            let mut file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                Ok(f) => Some(f),
                Err(e) => {
                    warn!("failed to open query audit log file {}: {}", log_path.display(), e);
                    None
                }
            };

            let mut current_size = file.as_ref().and_then(|f| f.metadata().ok()).map(|m| m.len()).unwrap_or(0);

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
                            format!("{:x}:{:x}:{:x}:{:x}::[masked]", segs[0], segs[1], segs[2], segs[3])
                        } else {
                            v6.to_string()
                        }
                    }
                };

                let line = format!(
                    "{}\t{}\t{}\t{}\t{}\t{}ms\t{}\n",
                    entry.timestamp_epoch_secs,
                    client_display,
                    entry.domain,
                    entry.qtype,
                    entry.status.as_str(),
                    entry.duration_ms,
                    entry.details.unwrap_or_else(|| "-".to_string())
                );

                let line_len = line.len() as u64;
                if current_size + line_len > max_bytes {
                    // rotate logs
                    drop(file.take());
                    rotate_files(&log_path, max_backups);
                    file = OpenOptions::new().create(true).append(true).open(&log_path).ok();
                    current_size = 0;
                }

                if let Some(ref mut f) = file {
                    if let Ok(()) = f.write_all(line.as_bytes()) {
                        let _ = f.flush();
                        current_size += line_len;
                    }
                }
            }
        });

        Arc::new(Self { tx })
    }

    pub fn log(&self, entry: QueryLogEntry) {
        let _ = self.tx.try_send(entry);
    }
}

// rotates file.log -> file.log.1 -> file.log.2
fn rotate_files(base_path: &Path, max_backups: usize) {
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

    #[tokio::test]
    async fn test_query_logger_file_write_and_ipcrypt() {
        let temp_dir = std::env::temp_dir().join(format!("albus_log_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let log_file = temp_dir.join("query.log");

        let ip_crypt = Some(Arc::new(IpCrypt::from_passphrase("test-secret-key")));
        let logger = QueryLogger::start(&log_file, ip_crypt, 1024, 2);

        logger.log(QueryLogEntry {
            timestamp_epoch_secs: 1700000000,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            domain: "tracker.ad.com".to_string(),
            qtype: 1,
            status: QueryStatus::BlockHagezi,
            duration_ms: 2,
            details: Some("hagezi".to_string()),
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let content = fs::read_to_string(&log_file).expect("log file should exist");
        assert!(content.contains("tracker.ad.com"));
        assert!(content.contains("BLOCK_HAGEZI"));
        assert!(content.contains("ip:")); // pseudonymized with ip: prefix

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
