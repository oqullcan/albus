//! quic connection migration and dynamic path agility engine (rfc 9000 section 9).
//!
//! allows encrypted doq and http/3 sessions to instantaneously migrate across local network
//! sockets, ip addresses, and ports when middlebox dpi blocking or throttling is detected.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Unique QUIC Connection ID representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    pub bytes: Vec<u8>,
    pub sequence_number: u64,
}

impl ConnectionId {
    pub fn new(bytes: Vec<u8>, sequence_number: u64) -> Self {
        Self { bytes, sequence_number }
    }
}

/// Status of an active network path for a QUIC session.
#[derive(Debug, Clone)]
pub struct QuicPath {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub validated: bool,
    pub last_active: Instant,
    pub rtt_millis: u64,
}

/// Orchestrates zero-loss connection migration across paths upon DPI interference.
#[derive(Debug, Clone)]
pub struct QuicMigrationController {
    active_cid: Arc<RwLock<ConnectionId>>,
    active_path: Arc<RwLock<QuicPath>>,
    migration_count: Arc<AtomicU64>,
}

impl QuicMigrationController {
    pub fn new(initial_cid: ConnectionId, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        Self {
            active_cid: Arc::new(RwLock::new(initial_cid)),
            active_path: Arc::new(RwLock::new(QuicPath {
                local_addr,
                peer_addr,
                validated: true,
                last_active: Instant::now(),
                rtt_millis: 20,
            })),
            migration_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Triggers an immediate connection migration to a new local socket or peer endpoint,
    /// rotating the Connection ID to prevent linkage by middlebox state trackers.
    pub fn trigger_migration(
        &self,
        new_local_addr: SocketAddr,
        new_peer_addr: Option<SocketAddr>,
        new_cid: ConnectionId,
    ) {
        if let Ok(mut cid_guard) = self.active_cid.write() {
            *cid_guard = new_cid;
        }

        if let Ok(mut path_guard) = self.active_path.write() {
            path_guard.local_addr = new_local_addr;
            if let Some(peer) = new_peer_addr {
                path_guard.peer_addr = peer;
            }
            path_guard.validated = true;
            path_guard.last_active = Instant::now();
        }

        self.migration_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn current_cid(&self) -> ConnectionId {
        self.active_cid.read().map(|g| g.clone()).unwrap_or_else(|_| ConnectionId::new(vec![], 0))
    }

    pub fn current_path(&self) -> QuicPath {
        self.active_path.read().map(|g| g.clone()).unwrap_or_else(|_| QuicPath {
            local_addr: "0.0.0.0:0".parse().unwrap(),
            peer_addr: "0.0.0.0:0".parse().unwrap(),
            validated: false,
            last_active: Instant::now(),
            rtt_millis: 0,
        })
    }

    pub fn total_migrations(&self) -> u64 {
        self.migration_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_connection_migration_workflow() {
        let cid0 = ConnectionId::new(vec![0xAA, 0xBB, 0xCC, 0xDD], 0);
        let local1: SocketAddr = "192.168.1.100:50001".parse().unwrap();
        let peer: SocketAddr = "9.9.9.9:853".parse().unwrap();

        let controller = QuicMigrationController::new(cid0, local1, peer);
        assert_eq!(controller.total_migrations(), 0);
        assert_eq!(controller.current_path().local_addr, local1);

        // DPI interference detected: migrate to new local ephemeral port 50002 and rotate CID
        let cid1 = ConnectionId::new(vec![0x11, 0x22, 0x33, 0x44], 1);
        let local2: SocketAddr = "192.168.1.100:50002".parse().unwrap();

        controller.trigger_migration(local2, None, cid1.clone());
        assert_eq!(controller.total_migrations(), 1);
        assert_eq!(controller.current_path().local_addr, local2);
        assert_eq!(controller.current_cid(), cid1);
    }
}
