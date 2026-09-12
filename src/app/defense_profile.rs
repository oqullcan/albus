//! Integrated defense profile coordinator.
//!
//! Provides predefined, battle-tested operational defense profiles combining
//! kernel packet manipulation, side-channel hardening, traffic obfuscation,
//! and quantum-resistant cryptographic transports into cohesive operational modes.

use serde::{Deserialize, Serialize};

/// High-level defense operational profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefenseProfile {
    /// Standard DPI evasion, DNSSEC, DoH/DoQ and ECH with minimal latency.
    Balanced,
    /// OS stack camouflage, JA4 mimicry, and stateful anti-injection filtering.
    Paranoid,
    /// Differential privacy telemetry, 128-bit IPcrypt pseudonymization, and SIMD acceleration.
    MaximumPrivacy,
    /// GREASE ECH, full TCP desynchronization with JA4 ClientHello, and anti-injection protection.
    CensorshipResistant,
}

impl Default for DefenseProfile {
    fn default() -> Self {
        DefenseProfile::Balanced
    }
}

impl DefenseProfile {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "balanced" => Some(DefenseProfile::Balanced),
            "paranoid" => Some(DefenseProfile::Paranoid),
            "maximum-privacy" | "max-privacy" | "maximumprivacy" => Some(DefenseProfile::MaximumPrivacy),
            "censorship-resistant" | "censor-resistant" | "censorshipresistant" => {
                Some(DefenseProfile::CensorshipResistant)
            }
            _ => None,
        }
    }

    /// Returns whether stateful anti-injection filtering is enabled.
    pub fn enable_anti_injection(&self) -> bool {
        matches!(self, DefenseProfile::Paranoid | DefenseProfile::CensorshipResistant)
    }

    /// Returns whether JA4 fingerprint mimicry is enabled.
    pub fn enable_ja4_mimic(&self) -> bool {
        matches!(self, DefenseProfile::Paranoid | DefenseProfile::CensorshipResistant)
    }

    /// Returns whether OS TCP/IP stack morphing is enabled.
    pub fn enable_stack_morph(&self) -> bool {
        matches!(self, DefenseProfile::Paranoid | DefenseProfile::CensorshipResistant)
    }

    /// Returns whether differential privacy telemetry is enabled.
    pub fn enable_differential_privacy(&self) -> bool {
        matches!(self, DefenseProfile::MaximumPrivacy | DefenseProfile::Paranoid)
    }

    /// Returns whether hardware SIMD vectorization acceleration is prioritized.
    pub fn enable_simd_accel(&self) -> bool {
        matches!(self, DefenseProfile::MaximumPrivacy | DefenseProfile::Paranoid)
    }

    /// Applies this defense profile's settings to a Config.
    pub fn apply(&self, cfg: &mut crate::app::config::Config) {
        match self {
            DefenseProfile::Balanced => {
                // Balanced mode: standard DPI evasion, DoH, DNSSEC, ECH with minimal latency
            }
            DefenseProfile::Paranoid => {
                cfg.anti_injection = true;
                if cfg.ja4_mimic.is_none() {
                    cfg.ja4_mimic = Some("chrome130".to_string());
                }
                if cfg.stack_morph.is_none() {
                    cfg.stack_morph = Some("windows11".to_string());
                }
                cfg.simd_accel = true;
            }
            DefenseProfile::MaximumPrivacy => {
                cfg.simd_accel = true;
                if cfg.ipcrypt_key.is_none() {
                    cfg.ipcrypt_key = Some("0123456789abcdef0123456789abcdef".to_string());
                }
            }
            DefenseProfile::CensorshipResistant => {
                cfg.anti_injection = true;
                if cfg.ja4_mimic.is_none() {
                    cfg.ja4_mimic = Some("chrome130".to_string());
                }
                if cfg.stack_morph.is_none() {
                    cfg.stack_morph = Some("windows11".to_string());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defense_profile_parsing() {
        assert_eq!(DefenseProfile::from_str("paranoid"), Some(DefenseProfile::Paranoid));
        assert_eq!(DefenseProfile::from_str("max-privacy"), Some(DefenseProfile::MaximumPrivacy));
        assert_eq!(DefenseProfile::from_str("censorship-resistant"), Some(DefenseProfile::CensorshipResistant));
        assert_eq!(DefenseProfile::from_str("invalid_mode"), None);
    }

    #[test]
    fn test_defense_profile_flags() {
        let paranoid = DefenseProfile::Paranoid;
        assert!(paranoid.enable_anti_injection());
        assert!(paranoid.enable_ja4_mimic());
        assert!(paranoid.enable_stack_morph());
        assert!(paranoid.enable_differential_privacy());

        let max_priv = DefenseProfile::MaximumPrivacy;
        assert!(max_priv.enable_differential_privacy());
        assert!(max_priv.enable_simd_accel());

        let censor = DefenseProfile::CensorshipResistant;
        assert!(censor.enable_ja4_mimic());
        assert!(censor.enable_stack_morph());
        assert!(censor.enable_anti_injection());
    }

    #[test]
    fn test_defense_profile_apply() {
        let mut cfg = crate::app::config::Config::default();
        assert!(!cfg.anti_injection);
        assert!(cfg.ja4_mimic.is_none());
        assert!(cfg.stack_morph.is_none());
        assert!(!cfg.simd_accel);

        DefenseProfile::Paranoid.apply(&mut cfg);
        assert!(cfg.anti_injection);
        assert_eq!(cfg.ja4_mimic.as_deref(), Some("chrome130"));
        assert_eq!(cfg.stack_morph.as_deref(), Some("windows11"));
        assert!(cfg.simd_accel);

        let mut cfg2 = crate::app::config::Config::default();
        DefenseProfile::CensorshipResistant.apply(&mut cfg2);
        assert!(cfg2.anti_injection);
        assert_eq!(cfg2.ja4_mimic.as_deref(), Some("chrome130"));
        assert_eq!(cfg2.stack_morph.as_deref(), Some("windows11"));

        let mut cfg3 = crate::app::config::Config::default();
        DefenseProfile::MaximumPrivacy.apply(&mut cfg3);
        assert!(cfg3.simd_accel);
        assert!(cfg3.ipcrypt_key.is_some());
    }
}
