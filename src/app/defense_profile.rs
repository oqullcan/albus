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
    /// Traffic morphing, OS stack camouflage, JA4 mimicry, active probe honeytokens,
    /// and stateful anti-injection filtering.
    Paranoid,
    /// Differential privacy telemetry, ZKP authorization, Privacy Pass blind tokens,
    /// 128-bit IPcrypt, and Sphinx multi-hop onion routing.
    MaximumPrivacy,
    /// Steganographic covert channels (HTTP/NTP), GREASE ECH, QUIC connection migration,
    /// and line-rate XDP driver drop.
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

    /// Returns whether traffic morphing (Poisson jitter and size quantization) is enabled.
    pub fn enable_traffic_morph(&self) -> bool {
        matches!(self, DefenseProfile::Paranoid | DefenseProfile::CensorshipResistant)
    }

    /// Returns whether active probe and replay defense is enabled.
    pub fn enable_active_probe_defense(&self) -> bool {
        matches!(self, DefenseProfile::Paranoid)
    }

    /// Returns whether stateful anti-injection filtering is enabled.
    pub fn enable_anti_injection(&self) -> bool {
        matches!(self, DefenseProfile::Paranoid | DefenseProfile::CensorshipResistant)
    }

    /// Returns whether JA4 fingerprint mimicry is enabled.
    pub fn enable_ja4_mimic(&self) -> bool {
        matches!(self, DefenseProfile::Paranoid | DefenseProfile::CensorshipResistant)
    }

    /// Returns whether Sphinx onion routing is enabled.
    pub fn enable_sphinx_routing(&self) -> bool {
        matches!(self, DefenseProfile::MaximumPrivacy)
    }

    /// Returns whether differential privacy telemetry is enabled.
    pub fn enable_differential_privacy(&self) -> bool {
        matches!(self, DefenseProfile::MaximumPrivacy | DefenseProfile::Paranoid)
    }

    /// Returns whether covert steganographic carriers are prioritized.
    pub fn enable_steganography(&self) -> bool {
        matches!(self, DefenseProfile::CensorshipResistant)
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
        assert!(paranoid.enable_traffic_morph());
        assert!(paranoid.enable_active_probe_defense());
        assert!(paranoid.enable_anti_injection());
        assert!(paranoid.enable_ja4_mimic());

        let max_priv = DefenseProfile::MaximumPrivacy;
        assert!(max_priv.enable_sphinx_routing());
        assert!(max_priv.enable_differential_privacy());

        let censor = DefenseProfile::CensorshipResistant;
        assert!(censor.enable_steganography());
        assert!(censor.enable_traffic_morph());
    }
}
