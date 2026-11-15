use std::convert::TryFrom;
use std::marker::PhantomData;

use serde::{Deserialize, Deserializer};

use super::hex::{decode_hex, FromHexString};
use super::newtype::{byte_newtype_fmt_redacted, byte_newtype_serialize};
use crate::hash::{Digest, Output, SrpHash};
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

impl<H: SrpHash> Proof<H> {
    /// The proof as a fixed array of the width `H` donates, so a caller that knows
    /// the hash avoids a length check. The stored proof is always one digest wide.
    pub fn as_array(&self) -> H::ProofBytes {
        H::ProofBytes::try_from(self.as_bytes())
            .ok()
            .expect("a proof is stored at exactly its hash width")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::DefaultHash;

    #[test]
    fn as_array_is_one_hash_wide_and_matches_as_bytes() {
        let proof = Proof::<DefaultHash>::try_from_bytes(&[7u8; 64]).expect("one SHA-512 digest");
        let array = proof.as_array();
        assert_eq!(array.len(), 64);
        assert_eq!(array.as_slice(), proof.as_bytes());
    }
}
