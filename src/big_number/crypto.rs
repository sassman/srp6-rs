//! The crypto-bigint backend.
//!
//! A signed magnitude over [`BoxedUint`]: SRP needs arbitrary widths for now,
//! and one intermediate (`B - k*g^x` on the client) is negative. The sign is
//! carried explicitly because the modular forms only hold non-negative values.

use std::fmt::Write as _;

use crypto_bigint::{BoxedUint, ConcatenatingMul, CtEq, NonZero, Odd};

#[derive(Clone)]
pub(super) struct Inner {
    magnitude: BoxedUint,
    negative: bool,
}

impl PartialEq for Inner {
    /// Compares the value, not the allocated precision.
    fn eq(&self, other: &Self) -> bool {
        self.negative == other.negative && self.to_vec() == other.to_vec()
    }
}

impl Inner {
    fn new(magnitude: BoxedUint, negative: bool) -> Self {
        let negative = negative && !magnitude.is_zero().to_bool();
        Self {
            magnitude,
            negative,
        }
    }

    pub(super) fn zero() -> Self {
        Self::new(BoxedUint::zero(), false)
    }

    pub(super) fn is_zero(&self) -> bool {
        self.magnitude.is_zero().to_bool()
    }

    /// Constant-time equality for equal-precision magnitudes. The sign is
    /// compared as a plain bool; it is public for the proofs this serves.
    pub(super) fn ct_eq(&self, other: &Self) -> bool {
        self.negative == other.negative && self.magnitude.ct_eq(&other.magnitude).to_bool()
    }

    /// `raw` is expected to be big endian.
    pub(super) fn from_bytes_be(raw: &[u8]) -> Self {
        if raw.is_empty() {
            return Self::zero();
        }
        Self::new(BoxedUint::from_be_slice_vartime(raw), false)
    }

    /// `raw` is expected to be little endian.
    pub(super) fn from_bytes_le(raw: &[u8]) -> Self {
        if raw.is_empty() {
            return Self::zero();
        }
        Self::new(BoxedUint::from_le_slice_vartime(raw), false)
    }

    pub(super) fn from_u32(n: u32) -> Self {
        Self::new(BoxedUint::from(n), false)
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

    /// Uppercase hex without leading zeroes; negative values keep the minus.
    pub(super) fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_owned();
        }

        let mut digits = String::with_capacity(self.magnitude.bits_vartime() as usize / 4 + 1);
        for byte in self.magnitude.to_be_bytes_trimmed_vartime().iter() {
            write!(digits, "{byte:02X}").expect("writing to a String cannot fail");
        }
        let digits = digits.trim_start_matches('0');

        let mut out = String::with_capacity(digits.len() + 1);
        if self.negative {
            out.push('-');
        }
        out.push_str(digits);
        out
    }

    pub(super) fn modpow(&self, exponent: &Self, modulo: &Self) -> Self {
        assert!(!exponent.negative, "negative exponents are not supported");
        assert!(
            !modulo.negative && !modulo.is_zero(),
            "modulus must be positive"
        );

        let modulus = &modulo.magnitude;
        let odd = Odd::new(modulus.clone())
            .into_option()
            .expect("modulus must be odd");

        // The Monty form requires the base to carry the modulus precision.
        let base = self.rem_euclid(modulus);
        let base = BoxedUint::from_be_slice(
            &base.to_be_bytes_trimmed_vartime(),
            modulus.bits_precision(),
        )
        .expect("the reduced base fits the modulus precision");

        Self::new(base.pow_mod(&exponent.magnitude, &odd), false)
    }

    /// The non-negative residue of `self` modulo `modulus`.
    fn rem_euclid(&self, modulus: &BoxedUint) -> BoxedUint {
        let nz = NonZero::new(modulus.clone())
            .into_option()
            .expect("modulus must be non-zero");
        let remainder = self.magnitude.rem(&nz);

        if self.negative && !remainder.is_zero().to_bool() {
            modulus.wrapping_sub(remainder)
        } else {
            remainder
        }
    }

    pub(super) fn add(&self, rhs: &Self) -> Self {
        match (self.negative, rhs.negative) {
            (false, false) => Self::new(self.magnitude.concatenating_add(&rhs.magnitude), false),
            (true, true) => Self::new(self.magnitude.concatenating_add(&rhs.magnitude), true),
            _ => {
                let (larger, smaller, negative) =
                    if self.magnitude.cmp_vartime(&rhs.magnitude).is_ge() {
                        (&self.magnitude, &rhs.magnitude, self.negative)
                    } else {
                        (&rhs.magnitude, &self.magnitude, rhs.negative)
                    };
                Self::new(larger.wrapping_sub(smaller), negative)
            }
        }
    }

    pub(super) fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.negated())
    }

    fn negated(&self) -> Self {
        Self::new(self.magnitude.clone(), !self.negative)
    }

    pub(super) fn mul(&self, rhs: &Self) -> Self {
        Self::new(
            self.magnitude.concatenating_mul(&rhs.magnitude),
            self.negative ^ rhs.negative,
        )
    }

    pub(super) fn rem(&self, rhs: &Self) -> Self {
        let nz = NonZero::new(rhs.magnitude.clone())
            .into_option()
            .expect("divisor is zero");
        Self::new(self.magnitude.rem(&nz), self.negative)
    }
}
