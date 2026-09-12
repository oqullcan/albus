//! tcp/ip os stack morphing and passive p0f/nmap signature evasion engine.
//!
//! normalizes and morphs outgoing tcp syn and raw packet parameters (options ordering,
//! window scale, initial window size, and ip ttl) to emulate specific client operating systems.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsProfile {
    Windows11,
    MacOsSequoia,
    Ios18,
    LinuxStock,
}

impl OsProfile {
    pub fn default_ttl(&self) -> u8 {
        match self {
            Self::Windows11 => 128,
            Self::MacOsSequoia | Self::Ios18 => 64,
            Self::LinuxStock => 64,
        }
    }

    pub fn default_window_size(&self) -> u16 {
        match self {
            Self::Windows11 => 64240,
            Self::MacOsSequoia => 65535,
            Self::Ios18 => 65535,
            Self::LinuxStock => 64240,
        }
    }

    /// Generates the byte representation of TCP options according to the OS fingerprint signature.
    pub fn build_tcp_options(&self, mss: u16, wscale: u8, tsval: u32, tsecr: u32) -> Vec<u8> {
        let mut opts = Vec::with_capacity(40);

        match self {
            Self::Windows11 => {
                // Windows 11 signature: MSS (4B) -> NOP (1B) -> WScale (3B) -> SACK Permitted (2B) -> Timestamp (10B)
                // MSS: Kind 2, Len 4
                opts.push(2);
                opts.push(4);
                opts.extend_from_slice(&mss.to_be_bytes());

                // NOP: Kind 1
                opts.push(1);

                // WScale: Kind 3, Len 3
                opts.push(3);
                opts.push(3);
                opts.push(wscale.min(8));

                // SACK Permitted: Kind 4, Len 2
                opts.push(4);
                opts.push(2);

                // Timestamp: Kind 8, Len 10
                opts.push(8);
                opts.push(10);
                opts.extend_from_slice(&tsval.to_be_bytes());
                opts.extend_from_slice(&tsecr.to_be_bytes());
            }
            Self::MacOsSequoia | Self::Ios18 => {
                // Apple signature: MSS (4B) -> NOP (1B) -> WScale (3B) -> NOP (1B) -> NOP (1B) -> Timestamp (10B) -> SACK Permitted (2B) -> EOL (2B pad)
                // MSS
                opts.push(2);
                opts.push(4);
                opts.extend_from_slice(&mss.to_be_bytes());

                // NOP
                opts.push(1);

                // WScale
                opts.push(3);
                opts.push(3);
                opts.push(wscale.min(6));

                // NOP, NOP
                opts.push(1);
                opts.push(1);

                // Timestamp
                opts.push(8);
                opts.push(10);
                opts.extend_from_slice(&tsval.to_be_bytes());
                opts.extend_from_slice(&tsecr.to_be_bytes());

                // SACK Permitted
                opts.push(4);
                opts.push(2);
            }
            Self::LinuxStock => {
                // Linux signature: MSS (4B) -> SACK Permitted (2B) -> Timestamp (10B) -> NOP (1B) -> WScale (3B)
                // MSS
                opts.push(2);
                opts.push(4);
                opts.extend_from_slice(&mss.to_be_bytes());

                // SACK Permitted
                opts.push(4);
                opts.push(2);

                // Timestamp
                opts.push(8);
                opts.push(10);
                opts.extend_from_slice(&tsval.to_be_bytes());
                opts.extend_from_slice(&tsecr.to_be_bytes());

                // NOP
                opts.push(1);

                // WScale
                opts.push(3);
                opts.push(3);
                opts.push(wscale);
            }
        }

        // Align options length to 32-bit (4-byte) boundary with NOP (1) or EOL (0)
        while (opts.len() % 4) != 0 {
            opts.push(1); // NOP
        }

        opts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_profiles_properties() {
        assert_eq!(OsProfile::Windows11.default_ttl(), 128);
        assert_eq!(OsProfile::MacOsSequoia.default_ttl(), 64);
        assert_eq!(OsProfile::Ios18.default_ttl(), 64);
        assert_eq!(OsProfile::LinuxStock.default_ttl(), 64);
    }

    #[test]
    fn test_tcp_options_alignment_and_ordering() {
        for profile in [
            OsProfile::Windows11,
            OsProfile::MacOsSequoia,
            OsProfile::Ios18,
            OsProfile::LinuxStock,
        ] {
            let opts = profile.build_tcp_options(1460, 7, 123456, 0);
            assert_eq!(opts.len() % 4, 0);
            assert!(opts.len() >= 20);

            // MSS is first for all profiles
            assert_eq!(opts[0], 2);
            assert_eq!(opts[1], 4);
            assert_eq!(&opts[2..4], &1460u16.to_be_bytes());
        }

        // Windows puts NOP after MSS
        let win_opts = OsProfile::Windows11.build_tcp_options(1460, 7, 100, 0);
        assert_eq!(win_opts[4], 1); // NOP
        assert_eq!(win_opts[5], 3); // WScale

        // Linux puts SACK after MSS
        let linux_opts = OsProfile::LinuxStock.build_tcp_options(1460, 7, 100, 0);
        assert_eq!(linux_opts[4], 4); // SACK Permitted
        assert_eq!(linux_opts[5], 2);
    }
}
