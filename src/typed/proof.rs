use std::marker::PhantomData;

use serde::{Deserialize, Deserializer};

use super::hex::{decode_hex, FromHexString};
use super::newtype::{byte_newtype_fmt_redacted, byte_newtype_serialize};
use crate::hash::{Digest, Output};
use crate::{error::Srp6Error, Result};
use subtle::ConstantTimeEq;

/// An `M1` or `M2` proof: exactly one hash-length byte string. The hash `H` is a
/// type marker, so a SHA-1 proof cannot be mixed with a SHA-512 exchange.
pub struct Proof<H>(Box<[u8]>, PhantomData<H>);

// Proofs get compared against attacker-supplied values, and a byte-by-byte `==`
// returns at the first mismatch: how long the comparison takes tells an attacker
// how many leading bytes were right, enough to guess a proof byte by byte.
// Compare in constant time instead.
impl<H> PartialEq for Proof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl<H> Eq for Proof<H> {}

impl<H> Clone for Proof<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<H> Proof<H> {
    pub fn as_bytes(&self) -> &[u8] {
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

impl<H: Digest> Proof<H> {
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected = <H as Digest>::output_size();
        if bytes.len() != expected {
            return Err(Srp6Error::InvalidProofLength {
                given: bytes.len(),
                expected,
            });
        }

        Ok(Self(Box::from(bytes), PhantomData))
    }

    pub(crate) fn from_hash(hash: Output<H>) -> Self {
        Self(Box::from(hash.as_slice()), PhantomData)
    }
}

byte_newtype_fmt_redacted!(<H> Proof, "Proof");
byte_newtype_serialize!(<H> Proof);

impl<H: Digest> FromHexString for Proof<H> {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::try_from_bytes(&decode_hex(hex)?)
    }
}

impl<'de, H: Digest> Deserialize<'de> for Proof<H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::try_from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
