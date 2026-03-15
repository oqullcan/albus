/// Best-effort process hardening applied at TUI startup.
///
/// The current implementation narrows post-crash artifact exposure for the
/// current process. On Windows it applies Windows Error Reporting flags. On
/// Unix-like hosts it lowers the core dump soft limit to zero, and on Linux it
/// also marks the process as non-dumpable. This remains a narrow platform FFI
/// exception to the usual `unsafe` ban because the OS API surface is the only
/// correct place to apply it.
pub(crate) fn startup_warning_from_env() -> Option<String> {
    #[cfg(windows)]
    {
        if hardening_enabled_from_env(std::env::var("ALBUS_WINDOWS_WER_HARDENING").ok().as_deref())
            && let Err(error) = platform::apply_default_wer_flags()
        {
            return Some(format!(
                "warning: Windows crash-report hardening could not be applied: {error}"
            ));
        }
    }

    #[cfg(unix)]
    {
        if hardening_enabled_from_env(
            std::env::var("ALBUS_UNIX_CORE_DUMP_HARDENING")
                .ok()
                .as_deref(),
        ) && let Err(error) = platform::apply_default_core_dump_hardening()
        {
            return Some(format!(
                "warning: Unix core-dump hardening could not be applied: {error}"
            ));
        }
    }

    None
}

fn hardening_enabled_from_env(value: Option<&str>) -> bool {
    let normalized = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !matches!(normalized.as_str(), "0" | "false" | "off")
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    type Dword = u32;
    type Handle = *mut c_void;
    type Hresult = i32;

    const WER_FAULT_REPORTING_FLAG_NOHEAP: Dword = 1;
    const WER_FAULT_REPORTING_FLAG_DISABLE_THREAD_SUSPENSION: Dword = 4;
    const WER_FAULT_REPORTING_DISABLE_SNAPSHOT_CRASH: Dword = 128;
    const WER_FAULT_REPORTING_DISABLE_SNAPSHOT_HANG: Dword = 256;

    pub(super) fn apply_default_wer_flags() -> Result<(), String> {
        let desired_flags = desired_wer_flags();
        set_process_wer_flags(desired_flags)?;

        if let Ok(effective_flags) = current_process_wer_flags()
            && effective_flags & desired_flags != desired_flags
        {
            return Err(format!(
                "effective WER flags were 0x{effective_flags:08X}, expected bits 0x{desired_flags:08X}"
            ));
        }

        Ok(())
    }

    pub(super) const fn desired_wer_flags() -> Dword {
        WER_FAULT_REPORTING_FLAG_NOHEAP
            | WER_FAULT_REPORTING_FLAG_DISABLE_THREAD_SUSPENSION
            | WER_FAULT_REPORTING_DISABLE_SNAPSHOT_CRASH
            | WER_FAULT_REPORTING_DISABLE_SNAPSHOT_HANG
    }

    pub(super) fn current_process_wer_flags() -> Result<Dword, String> {
        let mut flags = 0;

        // SAFETY: `WerGetFlags` requires a valid process handle and writable
        // pointer. `GetCurrentProcess` returns a pseudo-handle for this
        // process, and `flags` lives for the duration of the call.
        let hresult = unsafe { WerGetFlags(GetCurrentProcess(), &raw mut flags) };
        if hresult < 0 {
            return Err(format_hresult("WerGetFlags", hresult));
        }

        Ok(flags)
    }

    pub(super) fn set_process_wer_flags(flags: Dword) -> Result<(), String> {
        // SAFETY: `WerSetFlags` only reads the provided bitflags for the
        // current process. The value is a plain `u32` constructed from
        // constants defined in the Windows SDK.
        let hresult = unsafe { WerSetFlags(flags) };
        if hresult < 0 {
            return Err(format_hresult("WerSetFlags", hresult));
        }

        Ok(())
    }

    fn format_hresult(operation: &str, hresult: Hresult) -> String {
        format!(
            "{operation} returned HRESULT 0x{:08X}",
            hresult.cast_unsigned()
        )
    }

    #[link(name = "wer")]
    unsafe extern "system" {
        fn WerSetFlags(dwFlags: Dword) -> Hresult;
        fn WerGetFlags(hProcess: Handle, pdwFlags: *mut Dword) -> Hresult;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
    }
}

#[cfg(unix)]
mod platform {
    use std::{ffi::c_int, io};

    type RlimT = u64;

    const RLIMIT_CORE: c_int = 4;

    #[cfg(target_os = "linux")]
    const PR_GET_DUMPABLE: c_int = 3;
    #[cfg(target_os = "linux")]
    const PR_SET_DUMPABLE: c_int = 4;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct CoreLimits {
        pub(super) current: u64,
        pub(super) max: u64,
    }

    #[repr(C)]
    struct Rlimit {
        rlim_cur: RlimT,
        rlim_max: RlimT,
    }

    pub(super) fn apply_default_core_dump_hardening() -> Result<(), String> {
        let limits = current_core_limits()?;
        if limits.current != 0 {
            set_core_limit_current(0)?;

            let effective = current_core_limits()?;
            if effective.current != 0 {
                return Err(format!(
                    "effective core dump soft limit was {}, expected 0",
                    effective.current
                ));
            }
        }

        #[cfg(target_os = "linux")]
        {
            set_process_dumpable(false)?;
            if current_process_dumpable()? {
                return Err("process remained dumpable after hardening".to_owned());
            }
        }

        Ok(())
    }

    pub(super) fn current_core_limits() -> Result<CoreLimits, String> {
        let mut limits = Rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // SAFETY: `getrlimit` expects a valid resource constant and writable
        // output pointer. `RLIMIT_CORE` is a platform constant and `limits`
        // lives for the duration of the call.
        let result = unsafe { getrlimit(RLIMIT_CORE, &raw mut limits) };
        if result != 0 {
            return Err(format_errno("getrlimit"));
        }

        Ok(CoreLimits {
            current: limits.rlim_cur,
            max: limits.rlim_max,
        })
    }

    pub(super) fn set_core_limit_current(current: u64) -> Result<(), String> {
        let limits = current_core_limits()?;
        let updated = Rlimit {
            rlim_cur: current,
            rlim_max: limits.max,
        };

        // SAFETY: `setrlimit` expects a valid resource constant and readable
        // pointer to a C-compatible `rlimit` struct. `updated` lives for the
        // duration of the call and only lowers the soft core-dump limit.
        let result = unsafe { setrlimit(RLIMIT_CORE, &raw const updated) };
        if result != 0 {
            return Err(format_errno("setrlimit"));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn current_process_dumpable() -> Result<bool, String> {
        // SAFETY: `prctl` with `PR_GET_DUMPABLE` ignores the trailing
        // arguments and returns a small integer status for the current
        // process.
        let result = unsafe { prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) };
        if result < 0 {
            return Err(format_errno("prctl(PR_GET_DUMPABLE)"));
        }

        Ok(result != 0)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn set_process_dumpable(dumpable: bool) -> Result<(), String> {
        // SAFETY: `prctl` with `PR_SET_DUMPABLE` accepts a single integer
        // toggle for the current process and ignores the trailing zero
        // arguments.
        let result = unsafe { prctl(PR_SET_DUMPABLE, usize::from(dumpable), 0, 0, 0) };
        if result != 0 {
            return Err(format_errno("prctl(PR_SET_DUMPABLE)"));
        }

        Ok(())
    }

    fn format_errno(operation: &str) -> String {
        let error = io::Error::last_os_error();
        format!("{operation} failed: {error}")
    }

    unsafe extern "C" {
        fn getrlimit(resource: c_int, rlp: *mut Rlimit) -> c_int;
        fn setrlimit(resource: c_int, rlp: *const Rlimit) -> c_int;
        #[cfg(target_os = "linux")]
        fn prctl(option: c_int, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::hardening_enabled_from_env;

    #[cfg(unix)]
    fn running_in_github_actions() -> bool {
        matches!(
            std::env::var("GITHUB_ACTIONS")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    }

    #[test]
    fn process_hardening_defaults_to_enabled() {
        assert!(hardening_enabled_from_env(None));
    }

    #[test]
    fn process_hardening_accepts_falsey_opt_out_values() {
        for value in ["0", "false", "off", " FALSE "] {
            assert!(!hardening_enabled_from_env(Some(value)));
        }
    }

    #[test]
    fn process_hardening_treats_other_values_as_enabled() {
        for value in ["1", "true", "on", "unexpected"] {
            assert!(hardening_enabled_from_env(Some(value)));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_wer_hardening_call_completes_without_error() {
        let result = super::platform::apply_default_wer_flags();
        assert!(result.is_ok(), "{result:?}");
    }

    #[cfg(unix)]
    #[test]
    fn unix_core_dump_hardening_call_completes_without_error() -> Result<(), String> {
        if running_in_github_actions() {
            eprintln!(
                "skipping unix core-dump hardening test in GitHub Actions: runner policies can block rlimit and dumpability changes"
            );
            return Ok(());
        }

        let original_limits = super::platform::current_core_limits()?;
        #[cfg(target_os = "linux")]
        let original_dumpable = super::platform::current_process_dumpable()?;

        let result = super::platform::apply_default_core_dump_hardening();
        assert!(result.is_ok(), "{result:?}");

        let effective_limits = super::platform::current_core_limits()?;
        assert_eq!(effective_limits.current, 0);

        let restore_limits = super::platform::set_core_limit_current(original_limits.current);
        assert!(restore_limits.is_ok(), "{restore_limits:?}");

        #[cfg(target_os = "linux")]
        {
            let restore_dumpable = super::platform::set_process_dumpable(original_dumpable);
            assert!(restore_dumpable.is_ok(), "{restore_dumpable:?}");
        }

        Ok(())
    }
}
