//! The crypto-bigint backend.
//!
//! Values are unsigned: the calculus reduces modulo `N` before subtracting,
//! and the modular math lives in `primitives` on `BoxedMontyForm`.

use std::fmt::Write as _;

use crypto_bigint::{BoxedUint, CtEq};

#[derive(Clone)]
pub(super) struct Inner {
    magnitude: BoxedUint,
}

impl PartialEq for Inner {
    /// Compares the value, not the allocated precision.
    fn eq(&self, other: &Self) -> bool {
        self.to_vec() == other.to_vec()
    }
}

impl Inner {
    pub(super) fn zero() -> Self {
        Self {
            magnitude: BoxedUint::zero(),
        }
    }

    pub(super) fn is_zero(&self) -> bool {
        self.magnitude.is_zero().to_bool()
    }

    /// Constant-time equality for equal-precision magnitudes. It is public
    /// for the proofs this serves.
    pub(super) fn ct_eq(&self, other: &Self) -> bool {
        self.magnitude.ct_eq(&other.magnitude).to_bool()
    }

    /// `raw` is expected to be big endian.
    pub(super) fn from_bytes_be(raw: &[u8]) -> Self {
        if raw.is_empty() {
            return Self::zero();
        }
        Self {
            magnitude: BoxedUint::from_be_slice_vartime(raw),
        }
    }

    /// `raw` is expected to be little endian.
    pub(super) fn from_bytes_le(raw: &[u8]) -> Self {
        if raw.is_empty() {
            return Self::zero();
        }
        Self {
            magnitude: BoxedUint::from_le_slice_vartime(raw),
        }
    }

    pub(super) fn from_u32(n: u32) -> Self {
        Self {
            magnitude: BoxedUint::from(n),
        }
    }

    /// Big endian, without leading zeroes; zero is `[0]`.
    pub(super) fn to_vec(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }
        self.magnitude.to_be_bytes_trimmed_vartime().to_vec()
    }

    pub(super) fn num_bytes(&self) -> usize {
        (self.magnitude.bits_vartime() as usize).div_ceil(8)
    }

    /// Uppercase hex without leading zeroes.
    pub(super) fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_owned();
        }

        let mut digits = String::with_capacity(self.magnitude.bits_vartime() as usize / 4 + 1);
        for byte in self.magnitude.to_be_bytes_trimmed_vartime().iter() {
            write!(digits, "{byte:02X}").expect("writing to a String cannot fail");
        }

        digits.trim_start_matches('0').to_owned()
    }

    pub(super) fn as_boxed_uint(&self) -> &BoxedUint {
        &self.magnitude
    }
}
