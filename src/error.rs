use thiserror::Error;

use crate::big_number::BigNumber;
use crate::primitives::RawPublicKey;

#[derive(Error, Debug, PartialEq)]
pub enum Srp6Error {
    #[error(
        "The provided key length ({given:?} byte) does not match the expected ({expected:?} byte)"
    )]
    KeyLengthMismatch { given: usize, expected: usize },

    #[error("The provided proof length ({given:?} byte) does not match the expected ({expected:?} byte)")]
    InvalidProofLength { given: usize, expected: usize },

    #[error("The provided proof is invalid")]
    InvalidProof(BigNumber),

    #[error("The provided strong proof is invalid")]
    InvalidStrongProof(BigNumber),

    /// Carries the rejected value as a [`RawPublicKey`]: it is by definition an
    /// unvalidated public key, and a [`PublicKey`][crate::PublicKey] could not
    /// hold it.
    #[error("The provided public key is invalid")]
    InvalidPublicKey(RawPublicKey),

    /// The bytes did not decode to a non-zero element modulo the group's `N`.
    #[error("The provided bytes are not a valid field element of the group")]
    InvalidFieldElement,
}
