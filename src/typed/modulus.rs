use std::convert::TryFrom;
use std::marker::PhantomData;

use super::newtype::byte_newtype_fmt;
use crate::group::Group;

/// The prime modulus `N` of a closed group.
///
/// The bytes are in the group's own byte order, the one its wire uses;
/// [`std::fmt::Display`] prints them as uppercase hex.
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

    /// `N` as a fixed array of the group's width.
    pub fn as_array(&self) -> G::Bytes {
        G::Bytes::try_from(&self.bytes)
            .ok()
            .expect("the modulus is stored at exactly its group's width")
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

byte_newtype_fmt!(<G> Modulus, "Modulus");

impl<G: Group> From<Modulus<G>> for Vec<u8> {
    fn from(value: Modulus<G>) -> Self {
        value.to_vec()
    }
}
