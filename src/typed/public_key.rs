use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::hex::{decode_hex, write_hex, FromHexString};
use super::FieldElement;
use crate::group::{Group, GroupOps};
use crate::{error::Srp6Error, Result};

/// A peer's public key `A` or `B`.
///
/// This is a distinct type so a verifier or a bare field element cannot be
/// passed where a peer key is expected. Construction reuses the field-element
/// validation: a key is never `0 mod N`.
pub struct PublicKey<G: Group>(FieldElement<G>);

impl<G: Group> PublicKey<G> {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl<G: GroupOps> PublicKey<G> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        FieldElement::from_bytes(bytes).map(Self)
    }

    pub(crate) fn from_field(group: &G, value: &G::Field) -> Self {
        Self(FieldElement::from_field(group, value))
    }

    pub(crate) fn to_field(&self, group: &G) -> G::Field {
        self.0.to_field(group)
    }
}

impl<G: Group> Clone for PublicKey<G> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<G: Group> PartialEq for PublicKey<G> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<G: Group> Eq for PublicKey<G> {}

impl<G: Group> AsRef<[u8]> for PublicKey<G> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<G: Group> From<PublicKey<G>> for Vec<u8> {
    fn from(value: PublicKey<G>) -> Self {
        value.to_bytes()
    }
}

impl<G: GroupOps> TryFrom<Vec<u8>> for PublicKey<G> {
    type Error = Srp6Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes(&bytes)
    }
}

impl<G: GroupOps> TryFrom<&[u8]> for PublicKey<G> {
    type Error = Srp6Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl<G: GroupOps> FromHexString for PublicKey<G> {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(&decode_hex(hex)?)
    }
}

impl<G: Group> fmt::Display for PublicKey<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, self.as_bytes())
    }
}

impl<G: Group> fmt::Debug for PublicKey<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl<G: Group> Serialize for PublicKey<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de, G: GroupOps> Deserialize<'de> for PublicKey<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
