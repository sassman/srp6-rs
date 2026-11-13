use super::newtype::{byte_newtype_fmt, byte_newtype_serialize, field_wrapper_impls};
use super::FieldElement;
use crate::group::Group;

/// A peer's public key `A` or `B`.
///
/// This is a distinct type so a verifier or a bare field element cannot be
/// passed where a peer key is expected. Construction reuses the field-element
/// validation: a key is never `0 mod N`.
pub struct PublicKey<G: Group>(FieldElement<G>);

field_wrapper_impls!(PublicKey);
byte_newtype_fmt!(<G> PublicKey, "PublicKey");
byte_newtype_serialize!(<G> PublicKey);
