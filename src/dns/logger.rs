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
    BlockedName,
    AllowedName,
    AllowedIp,
    UncloakedCname,
    RebindRefused,
    BogonDrop,
    Cloak0ms,
    CacheHit,
    Canary,
    Captive,
    Undelegated,
    NxDomain,
    PqcDowngradeDrop,
    Refused,
}

impl QueryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::BlockHagezi => "BLOCK_HAGEZI",
            Self::BlockedName => "BLOCKED_NAME",
            Self::AllowedName => "ALLOWED_NAME",
            Self::AllowedIp => "ALLOWED_IP",
            Self::UncloakedCname => "UNCLOAKED_CNAME",
            Self::RebindRefused => "REBIND_REFUSED",
            Self::BogonDrop => "BOGON_DROP",
            Self::Cloak0ms => "CLOAK_0MS",
            Self::CacheHit => "CACHE_HIT",
            Self::Canary => "CANARY",
            Self::Captive => "CAPTIVE",
            Self::Undelegated => "UNDELEGATED",
            Self::NxDomain => "NXDOMAIN",
            Self::PqcDowngradeDrop => "PQC_DOWNGRADE_DROP",
            Self::Refused => "REFUSED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Tsv,
    Ltsv,
    Json,
}

impl LogFormat {
    pub fn parse_lenient(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "ltsv" => Self::Ltsv,
            "json" => Self::Json,
            _ => Self::Tsv,
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

pub fn format_query_log(
    entry: &QueryLogEntry,
    client_display: &str,
    safe_domain: &str,
    safe_details: &str,
    format: LogFormat,
) -> String {
    match format {
        LogFormat::Tsv => format!(
            "{}\t{}\t{}\t{}\t{}\t{}ms\t{}\n",
            entry.timestamp_epoch_secs,
            client_display,
            safe_domain,
            entry.qtype,
            entry.status.as_str(),
            entry.duration_ms,
            safe_details
        ),
        LogFormat::Ltsv => {
            let cached = if entry.status == QueryStatus::CacheHit { 1 } else { 0 };
            format!(
                "time:{}\thost:{}\tmessage:{}\ttype:{}\treturn:{}\tcached:{}\tduration:{}\tserver:{}\trelay:-\n",
                entry.timestamp_epoch_secs,
                client_display,
                safe_domain,
                entry.qtype,
                entry.status.as_str(),
                cached,
                entry.duration_ms,
                safe_details
            )
        }
        LogFormat::Json => {
            let cached = entry.status == QueryStatus::CacheHit;
            serde_json::json!({
                "time": entry.timestamp_epoch_secs,
                "host": client_display,
                "message": safe_domain,
                "type": entry.qtype,
                "return": entry.status.as_str(),
                "cached": cached,
                "duration_ms": entry.duration_ms,
                "server": safe_details,
            })
            .to_string()
                + "\n"
        }
    }
}

pub fn format_nx_log(
    entry: &QueryLogEntry,
    client_display: &str,
    safe_domain: &str,
    safe_details: &str,
    format: LogFormat,
) -> String {
    match format {
        LogFormat::Tsv => format!(
            "{}\t{}\t{}\t{}\t{}\t{}ms\t{}\n",
            entry.timestamp_epoch_secs,
            client_display,
            safe_domain,
            entry.qtype,
            entry.status.as_str(),
            entry.duration_ms,
            safe_details
        ),
        LogFormat::Ltsv => format!(
            "time:{}\thost:{}\tmessage:{}\ttype:{}\n",
            entry.timestamp_epoch_secs, client_display, safe_domain, entry.qtype
        ),
        LogFormat::Json => {
            serde_json::json!({
                "time": entry.timestamp_epoch_secs,
                "host": client_display,
                "message": safe_domain,
                "type": entry.qtype,
                "return": entry.status.as_str(),
                "duration_ms": entry.duration_ms,
                "server": safe_details,
            })
            .to_string()
                + "\n"
        }
    }
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

#[derive(Clone, Debug, Default)]
pub struct LoggerOptions {
    pub main_path: Option<PathBuf>,
    pub nx_path: Option<PathBuf>,
    pub blocked_names_path: Option<PathBuf>,
    pub blocked_ips_path: Option<PathBuf>,
    pub allowed_names_path: Option<PathBuf>,
    pub allowed_ips_path: Option<PathBuf>,
    pub main_format: LogFormat,
    pub nx_format: LogFormat,
    pub blocked_names_format: LogFormat,
    pub blocked_ips_format: LogFormat,
    pub allowed_names_format: LogFormat,
    pub allowed_ips_format: LogFormat,
    pub ip_crypt: Option<Arc<IpCrypt>>,
    pub max_bytes: u64,
    pub max_backups: usize,
    pub ignored_qtypes: Vec<String>,
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
        Self::start_with_formats(
            main_path,
            nx_path,
            ip_crypt,
            max_bytes,
            max_backups,
            LogFormat::Tsv,
            LogFormat::Tsv,
        )
    }

pub fn qtype_from_str(s: &str) -> Option<u16> {
    match s.trim().to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "HINFO" => Some(13),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "OPT" => Some(41),
        "DNSKEY" => Some(48),
        "HTTPS" => Some(65),
        _ => s.trim().parse::<u16>().ok(),
    }
}

    pub fn start_with_formats<P1: AsRef<Path>, P2: AsRef<Path>>(
        main_path: Option<P1>,
        nx_path: Option<P2>,
        ip_crypt: Option<Arc<IpCrypt>>,
        max_bytes: u64,
        max_backups: usize,
        main_format: LogFormat,
        nx_format: LogFormat,
    ) -> Arc<Self> {
        Self::start_with_options(
            main_path,
            nx_path,
            ip_crypt,
            max_bytes,
            max_backups,
            main_format,
            nx_format,
            vec![],
        )
    }

    pub fn start_with_options<P1: AsRef<Path>, P2: AsRef<Path>>(
        main_path: Option<P1>,
        nx_path: Option<P2>,
        ip_crypt: Option<Arc<IpCrypt>>,
        max_bytes: u64,
        max_backups: usize,
        main_format: LogFormat,
        nx_format: LogFormat,
        ignored_qtypes: Vec<String>,
    ) -> Arc<Self> {
        let opts = LoggerOptions {
            main_path: main_path.map(|p| p.as_ref().to_path_buf()),
            nx_path: nx_path.map(|p| p.as_ref().to_path_buf()),
            blocked_names_path: None,
            blocked_ips_path: None,
            allowed_names_path: None,
            allowed_ips_path: None,
            main_format,
            nx_format,
            blocked_names_format: LogFormat::Tsv,
            blocked_ips_format: LogFormat::Tsv,
            allowed_names_format: LogFormat::Tsv,
            allowed_ips_format: LogFormat::Tsv,
            ip_crypt,
            max_bytes,
            max_backups,
            ignored_qtypes,
        };
        Self::start_full(opts)
    }

    pub fn start_full(opts: LoggerOptions) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<QueryLogEntry>(2048);
        let ignored_set: std::collections::HashSet<u16> = opts
            .ignored_qtypes
            .iter()
            .filter_map(|s| Self::qtype_from_str(s))
            .collect();

        tokio::spawn(async move {
            let mut main_state = opts
                .main_path
                .map(|p| LogFileState::new(p, opts.max_bytes, opts.max_backups));
            let mut nx_state = opts
                .nx_path
                .map(|p| LogFileState::new(p, opts.max_bytes, opts.max_backups));
            let mut blocked_names_state = opts
                .blocked_names_path
                .map(|p| LogFileState::new(p, opts.max_bytes, opts.max_backups));
            let mut blocked_ips_state = opts
                .blocked_ips_path
                .map(|p| LogFileState::new(p, opts.max_bytes, opts.max_backups));
            let mut allowed_names_state = opts
                .allowed_names_path
                .map(|p| LogFileState::new(p, opts.max_bytes, opts.max_backups));
            let mut allowed_ips_state = opts
                .allowed_ips_path
                .map(|p| LogFileState::new(p, opts.max_bytes, opts.max_backups));

            while let Some(entry) = rx.recv().await {
                if ignored_set.contains(&entry.qtype) {
                    continue;
                }
                let client_display = match entry.client_ip {
                    IpAddr::V4(v4) => {
                        if let Some(ref crypt) = opts.ip_crypt {
                            format!("ip:{}", crypt.encrypt(v4))
                        } else {
                            v4.to_string()
                        }
                    }
                    IpAddr::V6(v6) => {
                        if opts.ip_crypt.is_some() {
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
                    sanitize_log_field(&entry.details.clone().unwrap_or_else(|| "-".to_string()));

                if let Some(ref mut main) = main_state {
                    let line = format_query_log(
                        &entry,
                        &client_display,
                        &safe_domain,
                        &safe_details,
                        opts.main_format,
                    );
                    main.write_line(&line);
                }

                if entry.status == QueryStatus::NxDomain {
                    if let Some(ref mut nx) = nx_state {
                        let line = format_nx_log(
                            &entry,
                            &client_display,
                            &safe_domain,
                            &safe_details,
                            opts.nx_format,
                        );
                        nx.write_line(&line);
                    }
                }

                if entry.status == QueryStatus::BlockHagezi
                    || entry.status == QueryStatus::BlockedName
                    || entry.status == QueryStatus::UncloakedCname
                {
                    if let Some(ref mut bn) = blocked_names_state {
                        let line = format_query_log(
                            &entry,
                            &client_display,
                            &safe_domain,
                            &safe_details,
                            opts.blocked_names_format,
                        );
                        bn.write_line(&line);
                    }
                }

                if entry.status == QueryStatus::BogonDrop {
                    if let Some(ref mut bi) = blocked_ips_state {
                        let line = format_query_log(
                            &entry,
                            &client_display,
                            &safe_domain,
                            &safe_details,
                            opts.blocked_ips_format,
                        );
                        bi.write_line(&line);
                    }
                }

                if entry.status == QueryStatus::AllowedName {
                    if let Some(ref mut an) = allowed_names_state {
                        let line = format_query_log(
                            &entry,
                            &client_display,
                            &safe_domain,
                            &safe_details,
                            opts.allowed_names_format,
                        );
                        an.write_line(&line);
                    }
                }

                if entry.status == QueryStatus::AllowedIp {
                    if let Some(ref mut ai) = allowed_ips_state {
                        let line = format_query_log(
                            &entry,
                            &client_display,
                            &safe_domain,
                            &safe_details,
                            opts.allowed_ips_format,
                        );
                        ai.write_line(&line);
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
        assert_eq!(QueryStatus::PqcDowngradeDrop.as_str(), "PQC_DOWNGRADE_DROP");
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

    #[test]
    fn test_ltsv_query_and_nx_log_formatting() {
        let entry = QueryLogEntry {
            timestamp_epoch_secs: 1700000000,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            domain: "example.com".to_string(),
            qtype: 1,
            status: QueryStatus::CacheHit,
            duration_ms: 1,
            details: Some("quad9".to_string()),
        };

        let ltsv_line = format_query_log(&entry, "192.168.1.10", "example.com", "quad9", LogFormat::Ltsv);
        assert_eq!(
            ltsv_line,
            "time:1700000000\thost:192.168.1.10\tmessage:example.com\ttype:1\treturn:CACHE_HIT\tcached:1\tduration:1\tserver:quad9\trelay:-\n"
        );

        let nx_entry = QueryLogEntry {
            timestamp_epoch_secs: 1700000005,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            domain: "invalid.domain".to_string(),
            qtype: 28,
            status: QueryStatus::NxDomain,
            duration_ms: 15,
            details: None,
        };

        let nx_ltsv = format_nx_log(&nx_entry, "10.0.0.5", "invalid.domain", "-", LogFormat::Ltsv);
        assert_eq!(
            nx_ltsv,
            "time:1700000005\thost:10.0.0.5\tmessage:invalid.domain\ttype:28\n"
        );
    }

    #[tokio::test]
    async fn test_dedicated_filter_logs() {
        let temp_dir = std::env::temp_dir().join(format!("albus_filter_log_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let blocked_names_file = temp_dir.join("blocked_names.log");
        let blocked_ips_file = temp_dir.join("blocked_ips.log");
        let allowed_names_file = temp_dir.join("allowed_names.log");

        let opts = LoggerOptions {
            main_path: None,
            nx_path: None,
            blocked_names_path: Some(blocked_names_file.clone()),
            blocked_ips_path: Some(blocked_ips_file.clone()),
            allowed_names_path: Some(allowed_names_file.clone()),
            allowed_ips_path: None,
            main_format: LogFormat::Tsv,
            nx_format: LogFormat::Tsv,
            blocked_names_format: LogFormat::Tsv,
            blocked_ips_format: LogFormat::Tsv,
            allowed_names_format: LogFormat::Tsv,
            allowed_ips_format: LogFormat::Tsv,
            ip_crypt: None,
            max_bytes: 1024 * 1024,
            max_backups: 1,
            ignored_qtypes: vec![],
        };

        let logger = QueryLogger::start_full(opts);

        logger.log(QueryLogEntry {
            timestamp_epoch_secs: 100,
            client_ip: "127.0.0.1".parse().unwrap(),
            domain: "ads.tracker.com".to_string(),
            qtype: 1,
            status: QueryStatus::BlockedName,
            duration_ms: 0,
            details: Some("blocklist".to_string()),
        });

        logger.log(QueryLogEntry {
            timestamp_epoch_secs: 101,
            client_ip: "127.0.0.1".parse().unwrap(),
            domain: "malware.host".to_string(),
            qtype: 1,
            status: QueryStatus::BogonDrop,
            duration_ms: 10,
            details: Some("bogon_filter".to_string()),
        });

        logger.log(QueryLogEntry {
            timestamp_epoch_secs: 102,
            client_ip: "127.0.0.1".parse().unwrap(),
            domain: "trusted.internal".to_string(),
            qtype: 1,
            status: QueryStatus::AllowedName,
            duration_ms: 0,
            details: Some("allowlist".to_string()),
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

        let bn_content = fs::read_to_string(&blocked_names_file).expect("blocked names log must exist");
        assert!(bn_content.contains("ads.tracker.com"));
        assert!(!bn_content.contains("malware.host"));

        let bi_content = fs::read_to_string(&blocked_ips_file).expect("blocked ips log must exist");
        assert!(bi_content.contains("malware.host"));
        assert!(!bi_content.contains("ads.tracker.com"));

        let an_content = fs::read_to_string(&allowed_names_file).expect("allowed names log must exist");
        assert!(an_content.contains("trusted.internal"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
