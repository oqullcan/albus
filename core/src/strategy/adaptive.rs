// in-memory self-healing strategy coordinator with automatic dpi failure escalation

use super::BypassMode;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct AdaptiveEvasionEngine {
    domain_modes: Mutex<HashMap<String, BypassMode>>,
    failure_counts: Mutex<HashMap<String, u32>>,
}

impl AdaptiveEvasionEngine {
    pub fn new() -> Self {
        Self {
            domain_modes: Mutex::new(HashMap::new()),
            failure_counts: Mutex::new(HashMap::new()),
        }
    }

    // gets the optimal current evasion mode for a domain
    pub fn get_strategy(&self, domain: &str, default_mode: BypassMode) -> BypassMode {
        let modes = self.domain_modes.lock().unwrap();
        if let Some(&mode) = modes.get(domain) {
            mode
        } else {
            default_mode
        }
    }

    // records a successful connection to preserve optimal low-latency mode
    pub fn record_success(&self, domain: &str) {
        let mut failures = self.failure_counts.lock().unwrap();
        failures.remove(domain);
    }

    // automatically escalates strategy if dpi resets or drops connection
    pub fn record_failure(&self, domain: &str) -> BypassMode {
        let mut failures = self.failure_counts.lock().unwrap();
        let count = failures.entry(domain.to_string()).or_insert(0);
        *count += 1;

        let mut modes = self.domain_modes.lock().unwrap();
        if *count >= 2 {
            // escalate to disorder evasion mode for aggressive deep packet inspection
            modes.insert(domain.to_string(), BypassMode::Disorder);
            BypassMode::Disorder
        } else {
            modes.insert(domain.to_string(), BypassMode::SniSplit);
            BypassMode::SniSplit
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_escalation() {
        let engine = AdaptiveEvasionEngine::new();
        let target = "blocked-site.com";

        // Initial default mode
        assert_eq!(engine.get_strategy(target, BypassMode::StealthAuto), BypassMode::StealthAuto);

        // 1st failure -> escalates to SniSplit
        let mode1 = engine.record_failure(target);
        assert_eq!(mode1, BypassMode::SniSplit);
        assert_eq!(engine.get_strategy(target, BypassMode::StealthAuto), BypassMode::SniSplit);

        // 2nd failure -> escalates to Disorder
        let mode2 = engine.record_failure(target);
        assert_eq!(mode2, BypassMode::Disorder);
        assert_eq!(engine.get_strategy(target, BypassMode::StealthAuto), BypassMode::Disorder);

        // Success resets failure count
        engine.record_success(target);
    }
}

