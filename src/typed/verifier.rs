use super::newtype::{byte_newtype_fmt_redacted, byte_newtype_serialize, field_wrapper_impls};
use super::FieldElement;
use crate::group::Group;

/// The server-stored password verifier `v`, a validated group element.
///
/// A distinct type from [`crate::PublicKey`] and the bare field elements `g`/`k`
/// so it cannot be mixed up with them. It is a secret (password-equivalent), so
/// its [`std::fmt::Debug`] is redacted; [`std::fmt::Display`] still yields the
/// hex when a caller explicitly asks for it.
pub struct Verifier<G: Group>(FieldElement<G>);

field_wrapper_impls!(Verifier);
byte_newtype_fmt_redacted!(<G> Verifier, "Verifier");
byte_newtype_serialize!(<G> Verifier);
