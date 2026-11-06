//! The num-bigint backend, selected unless the crypto-bigint feature is on.

use num_bigint::{BigInt, Sign};
use num_traits::Zero as _;

#[derive(PartialEq, Clone)]
pub(super) struct Inner(BigInt);

impl Inner {
    pub(super) fn zero() -> Self {
        Self(BigInt::zero())
    }

    pub(super) fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// `raw` is expected to be big endian.
    pub(super) fn from_bytes_be(raw: &[u8]) -> Self {
        Self(BigInt::from_bytes_be(Sign::Plus, raw))
    }

    /// `raw` is expected to be little endian.
    pub(super) fn from_bytes_le(raw: &[u8]) -> Self {
        Self(BigInt::from_bytes_le(Sign::Plus, raw))
    }

    pub(super) fn from_u32(n: u32) -> Self {
        Self(BigInt::from(n))
    }

    pub(super) fn from_bigint(a: BigInt) -> Self {
        Self(a)
    }

    /// Big endian, without leading zeroes; zero is `[0]`.
    pub(super) fn to_vec(&self) -> Vec<u8> {
        self.0.to_bytes_be().1
    }

    pub(super) fn num_bytes(&self) -> usize {
        self.0.bits().div_ceil(8) as usize
    }

    /// Uppercase hex without leading zeroes; negative values keep the minus.
    pub(super) fn to_hex(&self) -> String {
        self.0.to_str_radix(16).to_uppercase()
    }

    pub(super) fn modpow(&self, exponent: &Self, modulo: &Self) -> Self {
        Self(self.0.modpow(&exponent.0, &modulo.0))
    }

    pub(super) fn add(&self, rhs: &Self) -> Self {
        Self(&self.0 + &rhs.0)
    }

    pub(super) fn sub(&self, rhs: &Self) -> Self {
        Self(&self.0 - &rhs.0)
    }

    pub(super) fn mul(&self, rhs: &Self) -> Self {
        Self(&self.0 * &rhs.0)
    }

    pub(super) fn rem(&self, rhs: &Self) -> Self {
        Self(&self.0 % &rhs.0)
    }
}
