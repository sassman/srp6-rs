use thiserror::Error;

use crate::prelude::*;

#[derive(Error, Debug, PartialEq)]
pub enum Srp6Error {
    #[error(
        "The provided key length ({given:?} byte) does not match the expected ({expected:?} byte)"
    )]
    KeyLengthMismatch { given: usize, expected: usize },

    #[error("The provided proof is invalid")]
    InvalidProof(Proof),

    #[error("The provided strong proof is invalid")]
    InvalidStrongProof(StrongProof),

    /// Carries the rejected value as a [`RawPublicKey`]: it is by definition an
    /// unvalidated public key, and a [`PublicKey`] could not hold it.
    #[error("The provided public key is invalid")]
    InvalidPublicKey(RawPublicKey),
}
