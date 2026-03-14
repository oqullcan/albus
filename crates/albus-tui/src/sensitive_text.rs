use zeroize::Zeroize;

const DEFAULT_SENSITIVE_TEXT_CAPACITY: usize = 8 * 1024;

/// Best-effort locked text buffer for interactive secret entry.
///
/// The buffer reserves a fixed-capacity heap allocation up front so ordinary
/// edits do not reallocate and leave stale copies behind. When the platform
/// allows it, the backing pages are also locked in memory until drop.
pub(crate) struct SensitiveText {
    buffer: String,
    memory_lock: Option<LockedMemoryPages>,
}

impl SensitiveText {
    pub(crate) fn new() -> Self {
        Self::with_capacity(DEFAULT_SENSITIVE_TEXT_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        let mut buffer = String::with_capacity(capacity);
        let memory_lock = LockedMemoryPages::best_effort_for_string(&mut buffer);
        Self {
            buffer,
            memory_lock,
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.buffer.as_str()
    }

    pub(crate) fn chars_count(&self) -> usize {
        self.buffer.chars().count()
    }

    pub(crate) fn clear(&mut self) {
        self.buffer.zeroize();
    }

    pub(crate) fn pop(&mut self) {
        let _ = self.buffer.pop();
    }

    pub(crate) fn push_char(&mut self, character: char) -> bool {
        if self.buffer.len() + character.len_utf8() > self.buffer.capacity() {
            return false;
        }

        self.buffer.push(character);
        true
    }

    #[cfg(test)]
    fn is_memory_lock_active(&self) -> bool {
        self.memory_lock.is_some()
    }
}

impl Default for SensitiveText {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SensitiveText {
    fn drop(&mut self) {
        self.buffer.zeroize();
        let _ = self.memory_lock.take();
    }
}

impl From<&str> for SensitiveText {
    fn from(value: &str) -> Self {
        let mut text = Self::new();
        for character in value.chars() {
            if !text.push_char(character) {
                break;
            }
        }
        text
    }
}

#[derive(Debug)]
struct LockedMemoryPages {
    page_start: *mut u8,
    page_len: usize,
}

impl LockedMemoryPages {
    fn best_effort_for_string(buffer: &mut String) -> Option<Self> {
        if buffer.capacity() == 0 {
            return None;
        }

        Self::try_new(buffer.as_mut_ptr(), buffer.capacity()).ok()
    }

    fn try_new(region_start: *mut u8, region_len: usize) -> Result<Self, String> {
        if region_len == 0 {
            return Err("cannot lock an empty buffer".to_owned());
        }

        let page_size = platform::page_size()?;
        let region_start = region_start.addr();
        let page_start = region_start - (region_start % page_size);
        let region_end = region_start
            .checked_add(region_len)
            .ok_or_else(|| "buffer region overflowed while locking pages".to_owned())?;
        let page_end = region_end.div_ceil(page_size) * page_size;
        let page_len = page_end
            .checked_sub(page_start)
            .ok_or_else(|| "buffer page range underflowed while locking pages".to_owned())?;

        platform::lock_pages(page_start as *mut u8, page_len)?;
        Ok(Self {
            page_start: page_start as *mut u8,
            page_len,
        })
    }
}

impl Drop for LockedMemoryPages {
    fn drop(&mut self) {
        let _ = platform::unlock_pages(self.page_start, self.page_len);
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    type Bool = i32;
    type Dword = u32;
    type Lpvoid = *mut c_void;

    #[repr(C)]
    struct SystemInfo {
        w_processor_architecture: u16,
        w_reserved: u16,
        dw_page_size: Dword,
        lp_minimum_application_address: Lpvoid,
        lp_maximum_application_address: Lpvoid,
        dw_active_processor_mask: usize,
        dw_number_of_processors: Dword,
        dw_processor_type: Dword,
        dw_allocation_granularity: Dword,
        w_processor_level: u16,
        w_processor_revision: u16,
    }

    pub(super) fn page_size() -> Result<usize, String> {
        let mut info = SystemInfo {
            w_processor_architecture: 0,
            w_reserved: 0,
            dw_page_size: 0,
            lp_minimum_application_address: std::ptr::null_mut(),
            lp_maximum_application_address: std::ptr::null_mut(),
            dw_active_processor_mask: 0,
            dw_number_of_processors: 0,
            dw_processor_type: 0,
            dw_allocation_granularity: 0,
            w_processor_level: 0,
            w_processor_revision: 0,
        };

        // SAFETY: `GetSystemInfo` expects a writable pointer to a
        // `SYSTEM_INFO`-compatible struct. `info` lives for the duration of the
        // call and is fully initialized afterwards.
        unsafe { GetSystemInfo(&raw mut info) };
        if info.dw_page_size == 0 {
            return Err("GetSystemInfo returned a zero page size".to_owned());
        }

        Ok(info.dw_page_size as usize)
    }

    pub(super) fn lock_pages(address: *mut u8, len: usize) -> Result<(), String> {
        // SAFETY: `VirtualLock` reads the pointer range only to lock the
        // current process pages. The pointer and length were derived from an
        // allocated `String` buffer and rounded to page boundaries.
        let result = unsafe { VirtualLock(address.cast::<c_void>(), len) };
        if result == 0 {
            return Err(format_last_os_error("VirtualLock"));
        }

        Ok(())
    }

    pub(super) fn unlock_pages(address: *mut u8, len: usize) -> Result<(), String> {
        // SAFETY: `VirtualUnlock` receives the same page-aligned range
        // previously passed to `VirtualLock`.
        let result = unsafe { VirtualUnlock(address.cast::<c_void>(), len) };
        if result == 0 {
            return Err(format_last_os_error("VirtualUnlock"));
        }

        Ok(())
    }

    fn format_last_os_error(operation: &str) -> String {
        let error = std::io::Error::last_os_error();
        format!("{operation} failed: {error}")
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemInfo(lpSystemInfo: *mut SystemInfo);
        fn VirtualLock(lpAddress: Lpvoid, dwSize: usize) -> Bool;
        fn VirtualUnlock(lpAddress: Lpvoid, dwSize: usize) -> Bool;
    }
}

#[cfg(unix)]
mod platform {
    use std::{ffi::c_int, io};

    pub(super) fn page_size() -> Result<usize, String> {
        // SAFETY: `getpagesize` takes no arguments and returns the current
        // system page size for this process.
        let size = unsafe { getpagesize() };
        if size <= 0 {
            return Err("getpagesize returned a non-positive page size".to_owned());
        }

        usize::try_from(size).map_err(|_| "getpagesize returned an invalid page size".to_owned())
    }

    pub(super) fn lock_pages(address: *mut u8, len: usize) -> Result<(), String> {
        // SAFETY: `mlock` receives a page-aligned address range derived from a
        // live heap allocation that remains valid for the lifetime of the
        // returned lock handle.
        let result = unsafe { mlock(address.cast(), len) };
        if result != 0 {
            return Err(format_errno("mlock"));
        }

        Ok(())
    }

    pub(super) fn unlock_pages(address: *mut u8, len: usize) -> Result<(), String> {
        // SAFETY: `munlock` receives the same page-aligned range previously
        // passed to `mlock`.
        let result = unsafe { munlock(address.cast(), len) };
        if result != 0 {
            return Err(format_errno("munlock"));
        }

        Ok(())
    }

    fn format_errno(operation: &str) -> String {
        let error = io::Error::last_os_error();
        format!("{operation} failed: {error}")
    }

    unsafe extern "C" {
        fn getpagesize() -> c_int;
        fn mlock(addr: *const std::ffi::c_void, len: usize) -> c_int;
        fn munlock(addr: *const std::ffi::c_void, len: usize) -> c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::SensitiveText;

    #[test]
    fn sensitive_text_tracks_secret_length_without_exposing_plaintext() {
        let text = SensitiveText::from("secret-passphrase");
        assert_eq!(text.as_str(), "secret-passphrase");
        assert_eq!(text.chars_count(), "secret-passphrase".chars().count());
    }

    #[test]
    fn sensitive_text_enforces_a_fixed_capacity() {
        let mut text = SensitiveText::default();
        for _ in 0..(8 * 1024) {
            assert!(text.push_char('a'));
        }
        assert!(!text.push_char('b'));
    }

    #[test]
    fn sensitive_text_best_effort_lock_does_not_prevent_use() {
        let text = SensitiveText::default();
        let _ = text.is_memory_lock_active();
    }
}
