use core::fmt;

use zeroize::Zeroize;

/// Secret byte wrapper used for derived keys and other cryptographic material.
#[derive(Eq, PartialEq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Creates a new secret wrapper.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the number of stored secret bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the wrapped secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the secret bytes within the crate.
    #[must_use]
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Returns mutable access to the secret bytes within the crate.
    #[must_use]
    pub(crate) fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(format!("{secret:?}"), "SecretBytes(REDACTED)");
    }
}
