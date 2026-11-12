use std::convert::TryInto;

use super::hex::{decode_hex, FromHexString};
use super::newtype::byte_newtype_fmt_redacted;
use crate::hash::STRONG_SESSION_KEY_LENGTH;
use crate::{error::Srp6Error, Result};
use subtle::ConstantTimeEq;

/// The strong session key `K`: the interleaved hash of the premaster secret.
#[derive(Clone, Copy)]
pub struct StrongSessionKey([u8; STRONG_SESSION_KEY_LENGTH]);

// A session key is a secret, so `==` must not leak matching prefixes through
// its timing; the derive's short-circuit comparison would.
impl PartialEq for StrongSessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0[..].ct_eq(&other.0[..]).into()
    }
}

impl Eq for StrongSessionKey {}

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

byte_newtype_fmt_redacted!(StrongSessionKey, "StrongSessionKey");

impl FromHexString for StrongSessionKey {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::try_from_bytes(&decode_hex(hex)?)
    }
}
