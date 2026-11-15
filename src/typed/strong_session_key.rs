use std::marker::PhantomData;

use super::hex::{decode_hex, FromHexString};
use super::newtype::byte_newtype_fmt_redacted;
use crate::hash::{strong_session_key_len, Digest};
use crate::{error::Srp6Error, Result};
use subtle::ConstantTimeEq;

/// The strong session key `K`: the interleaved hash of the premaster secret, two
/// hashes wide. `H` is a type marker so a SHA-1 key cannot be mixed with a
/// SHA-512 exchange.
pub struct StrongSessionKey<H>(Box<[u8]>, PhantomData<H>);

// A session key is a secret, and a byte-by-byte `==` returns at the first
// mismatch: how long the comparison takes reveals how many leading bytes matched.
// Compare in constant time instead.
impl<H> PartialEq for StrongSessionKey<H> {
    fn eq(&self, other: &Self) -> bool {
        self.0[..].ct_eq(&other.0[..]).into()
    }
}

impl<H> Eq for StrongSessionKey<H> {}

impl<H> Clone for StrongSessionKey<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<H> StrongSessionKey<H> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl<H: Digest> StrongSessionKey<H> {
    /// Decodes `bytes`, which must be exactly two hashes long.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected = strong_session_key_len::<H>();
        if bytes.len() != expected {
            return Err(Srp6Error::KeyLengthMismatch {
                given: bytes.len(),
                expected,
            });
        }

        Ok(Self(Box::from(bytes), PhantomData))
    }

    pub(crate) fn from_key(key: Vec<u8>) -> Self {
        Self(key.into_boxed_slice(), PhantomData)
    }
}

byte_newtype_fmt_redacted!(<H> StrongSessionKey, "StrongSessionKey");

impl<H: Digest> FromHexString for StrongSessionKey<H> {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::try_from_bytes(&decode_hex(hex)?)
    }
}
