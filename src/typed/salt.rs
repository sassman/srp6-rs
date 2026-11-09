use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::hex::{decode_hex, write_hex, FromHexString};
use crate::Result;

/// A salt, as generated, stored and sent to the client.
///
/// Any byte string is a valid salt; [`crate::group::Group::SALT_BYTES`] only fixes what
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

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt({self})")
    }
}

impl Serialize for Salt {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

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
