use super::{Generator, MultiplierParameter, PrimeModulus};
use crate::hash::*;

/// `k = H(N | PAD(g))` (k = 3 for legacy SRP-6)
#[allow(non_snake_case)]
#[cfg(not(feature = "wow-1-12-1"))]
pub fn calculate_k<const KEY_LENGTH: usize>(
    N: &PrimeModulus,
    g: &Generator,
) -> MultiplierParameter {
    HashFunc::new()
        .chain(N.to_vec().as_slice())
        .chain(g.to_array_pad_zero_len(KEY_LENGTH))
        .into()
}

/// `k = H(N | PAD(g))` (k = 3 for legacy SRP-6)
#[cfg(feature = "wow-1-12-1")]
pub fn calculate_k<const KEY_LENGTH: usize>(
    _: &PrimeModulus,
    _: &Generator,
) -> MultiplierParameter {
    MultiplierParameter::from(3)
}
