use std::convert::TryFrom;

use std::marker::PhantomData;

use serde::{Deserialize, Deserializer};

use super::hex::{decode_hex, FromHexString};
use super::newtype::{byte_newtype_fmt, byte_newtype_serialize};
use crate::group::{Group, GroupOps};
use crate::{error::Srp6Error, Result};

/// A validated field element of group `G`, in canonical fixed-width bytes.
///
/// Construction decodes the bytes as a non-zero element modulo `N`; a value of
/// this type is therefore always a valid group element, and there is no way to
/// hold a degenerate one.
///
/// [`Verifier`] is the semantic name used for the server-stored `v`;
/// [`crate::PublicKey`] is a distinct type with its own validation.
pub struct FieldElement<G: Group> {
    bytes: Box<[u8]>,
    _group: PhantomData<G>,
}

/// The server-stored password verifier `v`.
pub type Verifier<G> = FieldElement<G>;

impl<G: Group> FieldElement<G> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl<G: GroupOps> FieldElement<G> {
    /// Decodes `bytes`, rejecting values wider than `N` or `0 mod N`.
    ///
    /// Shorter inputs are zero-padded to the group's fixed width, so
    /// [`FieldElement::to_vec`] always returns `N_BYTES` bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
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

    pub(crate) fn to_field(&self, group: &G) -> Result<G::Field> {
        group
            .field_from_bytes(&self.bytes)
            .ok_or(Srp6Error::InvalidFieldElement)
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

byte_newtype_fmt!(<G> FieldElement, "FieldElement");
byte_newtype_serialize!(<G> FieldElement);

impl<G: Group> From<FieldElement<G>> for Vec<u8> {
    fn from(value: FieldElement<G>) -> Self {
        value.to_vec()
    }
}

impl<G: GroupOps> TryFrom<Vec<u8>> for FieldElement<G> {
    type Error = Srp6Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from_bytes(&bytes)
    }
}

impl<G: GroupOps> TryFrom<&[u8]> for FieldElement<G> {
    type Error = Srp6Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::try_from_bytes(bytes)
    }
}

impl<G: GroupOps> FromHexString for FieldElement<G> {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::try_from_bytes(&decode_hex(hex)?)
    }
}

impl<'de, G: GroupOps> Deserialize<'de> for FieldElement<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::try_from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
