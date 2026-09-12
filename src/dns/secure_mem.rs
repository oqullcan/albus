//! secure memory protection, mlock page locking, and automatic zeroization.
//!
//! provides hardened memory structures that lock secret keys in physical ram
//! via linux mlock to prevent swap paging and memory dump disclosures.

use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Locks the memory range in physical RAM to prevent paging to swap.
#[inline]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return true;
    }
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Unlocks the memory range in physical RAM.
#[inline]
pub fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return true;
    }
    unsafe { libc::munlock(ptr as *const libc::c_void, len) == 0 }
}

/// A fixed-size array stored in locked physical RAM with automatic zeroization on drop.
pub struct SecureKey<const N: usize> {
    data: [u8; N],
    locked: bool,
}

impl<const N: usize> SecureKey<N> {
    /// Creates a new zero-initialized SecureKey and locks it in RAM.
    pub fn new_zeroed() -> Self {
        let mut key = Self {
            data: [0u8; N],
            locked: false,
        };
        key.locked = lock_memory(key.data.as_ptr(), N);
        key
    }

    /// Creates a new SecureKey from existing bytes, locking the buffer in RAM.
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        let mut key = Self {
            data: bytes,
            locked: false,
        };
        key.locked = lock_memory(key.data.as_ptr(), N);
        key
    }

    /// Returns whether this key was successfully locked in physical RAM.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Exposes raw byte slice securely.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Exposes raw mutable byte slice securely.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

impl<const N: usize> Deref for SecureKey<N> {
    type Target = [u8; N];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for SecureKey<N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> Drop for SecureKey<N> {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.locked {
            unlock_memory(self.data.as_ptr(), N);
            self.locked = false;
        }
    }
}

impl<const N: usize> PartialEq for SecureKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<const N: usize> Eq for SecureKey<N> {}

impl<const N: usize> Clone for SecureKey<N> {
    fn clone(&self) -> Self {
        Self::from_bytes(self.data)
    }
}

impl<const N: usize> fmt::Debug for SecureKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecureKey<{} bytes> {{ locked: {}, data: REDACTED }}",
            N, self.locked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_key_lifecycle_and_redaction() {
        let secret = [0x42u8; 32];
        let mut key: SecureKey<32> = SecureKey::from_bytes(secret);

        assert_eq!(&*key, &secret);
        assert_eq!(key.as_bytes(), &secret);

        // verify debug string does not reveal secret
        let debug_repr = format!("{:?}", key);
        assert!(debug_repr.contains("REDACTED"));
        assert!(!debug_repr.contains("42"));

        // test mutation
        key[0] = 0x99;
        assert_eq!(key[0], 0x99);
    }

    #[test]
    fn test_secure_key_zeroed() {
        let key: SecureKey<16> = SecureKey::new_zeroed();
        assert_eq!(&*key, &[0u8; 16]);
    }
}
