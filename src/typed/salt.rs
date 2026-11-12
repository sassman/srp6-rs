use serde::{Deserialize, Deserializer};

use super::hex::{decode_hex, FromHexString};
use super::newtype::{byte_newtype_fmt, byte_newtype_serialize};
use crate::Result;

/// A salt, as generated, stored and sent to the client.
///
/// Any byte string is a valid salt; [`crate::Srp6::salt_bytes`] only fixes what
/// [`crate::Srp6::generate_new_user_secrets`] draws.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt(Box<[u8]>);

impl Salt {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into().into_boxed_slice())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<Vec<u8>> for Salt {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for Salt {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl From<Salt> for Vec<u8> {
    fn from(salt: Salt) -> Self {
        salt.to_vec()
    }
}

byte_newtype_fmt!(Salt, "Salt");
byte_newtype_serialize!(Salt);

impl FromHexString for Salt {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::from(decode_hex(hex)?))
    }
}

impl<'de> Deserialize<'de> for Salt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self::from(bytes))
    }
}
