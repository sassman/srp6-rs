use std::convert::TryInto;

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::hex::{decode_hex, write_hex, FromHexString};
use crate::hash::HASH_LENGTH;
use crate::{error::Srp6Error, Result};
use subtle::ConstantTimeEq;

/// An `M1` or `M2` proof: exactly one hash-length byte string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof([u8; HASH_LENGTH]);

impl Proof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
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

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Constant-time equality, for comparing a received proof with an expected one.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0[..].ct_eq(&other.0[..]).into()
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Proof({self})")
    }
}

impl Serialize for Proof {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl FromHexString for Proof {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(&decode_hex(hex)?)
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
