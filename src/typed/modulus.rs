use std::fmt;
use std::marker::PhantomData;

use super::hex::write_hex;
use crate::group::Group;

/// The prime modulus `N` of a closed group.
///
/// The bytes are the group's canonical big-endian encoding; [`fmt::Display`]
/// prints them as uppercase hex.
pub struct Modulus<G: Group> {
    bytes: Box<[u8]>,
    _group: PhantomData<G>,
}

impl<G: Group> Modulus<G> {
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into_boxed_slice(),
            _group: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl<G: Group> Clone for Modulus<G> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _group: PhantomData,
        }
    }
}

impl<G: Group> PartialEq for Modulus<G> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<G: Group> Eq for Modulus<G> {}

impl<G: Group> AsRef<[u8]> for Modulus<G> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<G: Group> From<Modulus<G>> for Vec<u8> {
    fn from(value: Modulus<G>) -> Self {
        value.to_vec()
    }
}

impl<G: Group> fmt::Display for Modulus<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.bytes)
    }
}

impl<G: Group> fmt::Debug for Modulus<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Modulus({self})")
    }
}
