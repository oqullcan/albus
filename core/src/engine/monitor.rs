// in-memory zero-log connection event ring buffer and live activity pulse tracker

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(serde::Serialize, Clone, Debug)]
pub struct ConnectionEvent {
    pub time: String,
    pub target: String,
    pub strategy: String,
    pub status: String,
}

pub struct ActivityMonitor {
    events: Mutex<VecDeque<ConnectionEvent>>,
    pulse_samples: Mutex<VecDeque<u32>>,
    current_tick_count: AtomicU32,
    bytes_in_sec: AtomicU64,
    current_throughput_bps: AtomicU64,
}

impl ActivityMonitor {
    pub fn new() -> Self {
        let mut initial_pulse = VecDeque::with_capacity(20);
        for _ in 0..20 {
            initial_pulse.push_back(0);
        }

        Self {
            events: Mutex::new(VecDeque::with_capacity(10)),
            pulse_samples: Mutex::new(initial_pulse),
            current_tick_count: AtomicU32::new(0),
            bytes_in_sec: AtomicU64::new(0),
            current_throughput_bps: AtomicU64::new(0),
        }
    }

    // records a live connection event in ram-only ring buffer
    pub fn record_event(&self, target: &str, strategy: &str, status: &str) {
        self.current_tick_count.fetch_add(1, Ordering::Relaxed);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let hours = (now / 3600) % 24;
        let mins = (now / 60) % 60;
        let secs = now % 60;
        let time_str = format!("{:02}:{:02}:{:02}", hours, mins, secs);

        let mut events = self.events.lock().unwrap();
        if events.len() >= 8 {
            events.pop_front();
        }

        events.push_back(ConnectionEvent {
            time: time_str,
            target: target.to_string(),
            strategy: strategy.to_string(),
            status: status.to_string(),
        });
    }

    // records transferred bytes for live throughput calculation
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_in_sec.fetch_add(bytes, Ordering::Relaxed);
    }

    // tick pulse updates the live rolling activity graph and throughput window
    pub fn tick_pulse(&self) {
        let count = self.current_tick_count.swap(0, Ordering::Relaxed);
        let bytes = self.bytes_in_sec.swap(0, Ordering::Relaxed);
        self.current_throughput_bps.store(bytes, Ordering::Relaxed);

        let mut samples = self.pulse_samples.lock().unwrap();
        if samples.len() >= 20 {
            samples.pop_front();
        }
        samples.push_back(count);
    }

    pub fn get_throughput_bps(&self) -> u64 {
        self.current_throughput_bps.load(Ordering::Relaxed)
    }

    pub fn get_throughput_str(&self) -> String {
        let bytes = self.get_throughput_bps();
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.2} GB/s", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.1} MB/s", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{} KB/s", bytes / 1024)
        } else {
            format!("{} B/s", bytes)
        }
    }

    pub fn get_events(&self) -> Vec<ConnectionEvent> {
        self.events.lock().unwrap().iter().cloned().collect()
    }

    pub fn get_pulse(&self) -> Vec<u32> {
        self.pulse_samples.lock().unwrap().iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_monitor_throughput() {
        let monitor = ActivityMonitor::new();
        monitor.record_bytes(1024 * 512); // 512 KB
        assert_eq!(monitor.get_throughput_bps(), 0); // before tick

        monitor.tick_pulse();
        assert_eq!(monitor.get_throughput_bps(), 1024 * 512);
        assert_eq!(monitor.get_throughput_str(), "512 KB/s");

        monitor.tick_pulse();
        assert_eq!(monitor.get_throughput_bps(), 0);
        assert_eq!(monitor.get_throughput_str(), "0 B/s");
    }
}

