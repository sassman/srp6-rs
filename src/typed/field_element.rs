use std::convert::TryFrom;

use std::fmt;
use std::marker::PhantomData;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::hex::{decode_hex, write_hex, FromHexString};
use crate::group::{Group, GroupOps};
use crate::{error::Srp6Error, Result};

/// A validated field element of group `G`, in canonical fixed-width bytes.
///
/// Construction decodes the bytes as a non-zero element modulo `N`; a value of
/// this type is therefore always a valid group element, and there is no way to
/// hold a degenerate one.
///
/// [`Verifier`] and [`PublicKey`] are the semantic names used in the handshake;
/// both carry this same validation.
pub struct FieldElement<G: Group> {
    bytes: Box<[u8]>,
    _group: PhantomData<G>,
}

/// The server-stored password verifier `v`.
pub type Verifier<G> = FieldElement<G>;

/// A peer's public key `A` or `B`.
pub type PublicKey<G> = FieldElement<G>;

impl<G: Group> FieldElement<G> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl<G: GroupOps> FieldElement<G> {
    /// Decodes `bytes`, rejecting values wider than `N` or `0 mod N`.
    ///
    /// Shorter inputs are zero-padded to the group's fixed width, so
    /// [`FieldElement::to_bytes`] always returns `N_BYTES` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let group = G::default();
        let field = group
            .field_from_bytes(bytes)
            .ok_or(Srp6Error::InvalidFieldElement)?;

        Ok(Self::from_field(&group, &field))
    }

    pub(crate) fn from_field(group: &G, value: &G::Field) -> Self {
        Self {
            bytes: group.field_to_bytes(value).into_boxed_slice(),
            _group: PhantomData,
        }
    }

    pub(crate) fn to_field(&self, group: &G) -> G::Field {
        group
            .field_from_bytes(&self.bytes)
            .expect("the bytes were validated when the value was built")
    }
}

impl<G: Group> Clone for FieldElement<G> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _group: PhantomData,
        }
    }
}

impl<G: Group> PartialEq for FieldElement<G> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<G: Group> Eq for FieldElement<G> {}

impl<G: Group> AsRef<[u8]> for FieldElement<G> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<G: Group> From<FieldElement<G>> for Vec<u8> {
    fn from(value: FieldElement<G>) -> Self {
        value.to_bytes()
    }
}

impl<G: GroupOps> TryFrom<Vec<u8>> for FieldElement<G> {
    type Error = Srp6Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes(&bytes)
    }
}

impl<G: GroupOps> TryFrom<&[u8]> for FieldElement<G> {
    type Error = Srp6Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl<G: GroupOps> FromHexString for FieldElement<G> {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(&decode_hex(hex)?)
    }
}

impl<G: Group> fmt::Display for FieldElement<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.bytes)
    }
}

impl<G: Group> fmt::Debug for FieldElement<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement({self})")
    }
}

impl<G: Group> Serialize for FieldElement<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de, G: GroupOps> Deserialize<'de> for FieldElement<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
