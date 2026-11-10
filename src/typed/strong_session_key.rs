use std::convert::TryInto;

use std::fmt;

use super::hex::{decode_hex, write_hex, FromHexString};
use crate::hash::STRONG_SESSION_KEY_LENGTH;
use crate::{error::Srp6Error, Result};

/// The strong session key `K`: the interleaved hash of the premaster secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StrongSessionKey([u8; STRONG_SESSION_KEY_LENGTH]);

impl StrongSessionKey {
    /// Decodes `bytes`, which must be exactly `STRONG_SESSION_KEY_LENGTH` long.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; STRONG_SESSION_KEY_LENGTH] =
            bytes.try_into().map_err(|_| Srp6Error::KeyLengthMismatch {
                given: bytes.len(),
                expected: STRONG_SESSION_KEY_LENGTH,
            })?;

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; STRONG_SESSION_KEY_LENGTH] {
        &self.0
    }

    pub(crate) fn from_key(key: [u8; STRONG_SESSION_KEY_LENGTH]) -> Self {
        Self(key)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<[u8]> for StrongSessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHexString for StrongSessionKey {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::try_from_bytes(&decode_hex(hex)?)
    }
}

impl fmt::Display for StrongSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for StrongSessionKey {
    // The session secret must not leak through `{:?}` logging or a derived
    // Debug on a surrounding struct. `Display` still prints the hex for callers
    // that explicitly ask for it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StrongSessionKey(<redacted>)")
    }
}
