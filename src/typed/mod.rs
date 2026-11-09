//! The typed SRP6 handshake over the closed groups.
//!
//! The boundary is byte-oriented: [`Salt`], [`FieldElement`] and its
//! [`Verifier`] name, [`PublicKey`], [`Proof`] and [`StrongSessionKey`] are the
//! values a caller handles. The group arithmetic and its backend stay inside
//! this module, so no crypto-bigint type reaches the public API.

mod field_element;
mod handshake;
mod hex;
mod proof;
mod public_key;
mod salt;
mod srp6;
pub(crate) mod steps;
mod strong_session_key;

#[cfg(test)]
mod tests;

pub use field_element::{FieldElement, Verifier};
pub use handshake::{
    Handshake, HandshakeProof, HandshakeProofVerifier, StrongProofVerifier, UserSecrets,
};
pub use hex::FromHexString;
pub use proof::Proof;
pub use public_key::PublicKey;
pub use salt::Salt;
pub use srp6::Srp6;
pub use strong_session_key::StrongSessionKey;
