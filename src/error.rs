use thiserror::Error;

use crate::typed::Proof;

#[derive(Error, Debug, PartialEq)]
pub enum Srp6Error {
    #[error(
        "The provided key length ({given:?} byte) does not match the expected ({expected:?} byte)"
    )]
    KeyLengthMismatch { given: usize, expected: usize },

    #[error("The provided proof length ({given:?} byte) does not match the expected ({expected:?} byte)")]
    InvalidProofLength { given: usize, expected: usize },

    #[error("The provided proof is invalid")]
    InvalidProof(Proof),

    #[error("The provided strong proof is invalid")]
    InvalidStrongProof(Proof),

    /// Carries the bytes that failed the `0 mod N` check.
    #[error("The provided public key is invalid")]
    InvalidPublicKey(Vec<u8>),

    /// The bytes did not decode to a non-zero element modulo the group's `N`.
    #[error("The provided bytes are not a valid field element of the group")]
    InvalidFieldElement,

    /// The string was not an even-length run of hex digits.
    #[error("The provided string is not an even-length hex string")]
    InvalidHexString,
}
