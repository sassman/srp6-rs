use std::convert::TryInto;

use serde::{Deserialize, Deserializer};

use super::hex::{decode_hex, FromHexString};
use super::newtype::{byte_newtype_fmt_redacted, byte_newtype_serialize};
use crate::hash::{Hash, HASH_LENGTH};
use crate::{error::Srp6Error, Result};
use subtle::ConstantTimeEq;

/// An `M1` or `M2` proof: exactly one hash-length byte string.
#[derive(Clone, Copy)]
pub struct Proof([u8; HASH_LENGTH]);

// Proofs get compared against attacker-supplied values, so `==` must not be a
// timing oracle; the derive's short-circuit comparison would be one.
impl PartialEq for Proof {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Proof {}

impl Proof {
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; HASH_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| Srp6Error::InvalidProofLength {
                    given: bytes.len(),
                    expected: HASH_LENGTH,
                })?;

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LENGTH] {
        &self.0
    }

    pub(crate) fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Constant-time equality, for comparing a received proof with an expected one.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0[..].ct_eq(&other.0[..]).into()
    }
}

byte_newtype_fmt_redacted!(Proof, "Proof");
byte_newtype_serialize!(Proof);

impl FromHexString for Proof {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::try_from_bytes(&decode_hex(hex)?)
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::try_from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
