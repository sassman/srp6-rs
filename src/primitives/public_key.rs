use std::fmt::{Display, Formatter};

use super::montgomery::{field, field_bytes, is_zero_mod, monty_params};
use super::{Generator, MultiplierParameter, PasswordVerifier, PrimeModulus, PrivateKey};
use crate::big_number::BigNumber;
use crate::{error::Srp6Error, Result};

/// Refers to a Public shared key called A (user), B (server)
///
/// Unlike the other primitives, [`PublicKey`] is not a plain alias to
/// [`BigNumber`]. It can only be built through [`PublicKey::new`], which
/// enforces the RFC 5054 §2.5.4 safeguard: "abort if \[the\] value ... is 0 mod N".
/// This makes it impossible to hold a degenerate key (0, `N`, or any multiple
/// of `N`) in a value of this type.
#[doc(alias("A", "B"))]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PublicKey(BigNumber);

impl PublicKey {
    /// Validates `value` and wraps it into a [`PublicKey`].
    ///
    /// Per [RFC 5054 §2.5.4](https://datatracker.ietf.org/doc/html/rfc5054#section-2.5.4),
    /// a host or client must "abort if \[the received public key\] % N is zero",
    /// since a degenerate key of that shape lets a hostile peer drive the
    /// shared session key to a value it already knows. This constructor is
    /// the only way to obtain a [`PublicKey`], so that guarantee holds for
    /// every value of this type, not just the ones checked right before use.
    pub(crate) fn new(value: BigNumber, n: &PrimeModulus) -> Result<Self> {
        if is_zero_mod(&value, n) {
            return Err(Srp6Error::InvalidPublicKey(value.to_vec()));
        }

        Ok(Self(value))
    }

    /// The runtime-length form of [`BigNumber::to_array_pad_zero`].
    pub(crate) fn to_array_pad_zero_len(&self, len: usize) -> Vec<u8> {
        self.0.to_array_pad_zero_len(len)
    }

    /// Big-endian bytes. See [`BigNumber::to_vec`].
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Access to the inner [`BigNumber`] for arithmetic. Deliberately not a
    /// [`std::ops::Deref`] impl, so the wrapper stays visible wherever the
    /// number is used.
    pub(crate) fn as_bignum(&self) -> &BigNumber {
        &self.0
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// `A` is the [`PublicKey`] of the client
/// formula: `A = g^a % N`
///
/// # Errors
/// [`Srp6Error::InvalidPublicKey`] if the result is `0 mod N`. For a prime
/// `N` and a generator `g < N` that cannot happen, but `N` is supplied by
/// the caller and never proven prime: with a degenerate group such as
/// `N = 4, g = 2, a = 2` the result is 0. Constructing through
/// [`PublicKey::new`] keeps that a `Result` rather than a panic.
#[allow(non_snake_case)]
pub(crate) fn calculate_pubkey_A(
    N: &PrimeModulus,
    g: &Generator,
    a: &PrivateKey,
) -> Result<PublicKey> {
    let params = monty_params(N);
    let public = field(g, &params).pow(a.as_boxed_uint());

    PublicKey::new(BigNumber::from_bytes_be(&field_bytes(&public)), N)
}

/// `B` is the host's public key
/// `B = kv + g^b`
///
/// # Errors
/// [`Srp6Error::InvalidPublicKey`] if the result is `0 mod N`. Unlike
/// [`calculate_pubkey_A`], `B` is a sum reduced mod `N`, so `k*v = -g^b`
/// lands on 0 even for a well formed group. It is vanishingly unlikely,
/// and the client rejects such a `B` on receipt anyway, but the host
/// should not hand one out: draw a fresh `b` and call again.
#[allow(non_snake_case)]
pub(crate) fn calculate_pubkey_B(
    N: &PrimeModulus,
    k: &MultiplierParameter,
    g: &Generator,
    v: &PasswordVerifier,
    b: &PrivateKey,
) -> Result<PublicKey> {
    let params = monty_params(N);
    let public = field(k, &params)
        .mul(&field(v, &params))
        .add(&field(g, &params).pow(b.as_boxed_uint()));

    PublicKey::new(BigNumber::from_bytes_be(&field_bytes(&public)), N)
}
