use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, NonZero, Odd,
};

use super::PrimeModulus;
use crate::big_number::BigNumber;

/// The Montgomery parameters for the group modulus `N`.
pub(super) fn monty_params(n: &PrimeModulus) -> BoxedMontyParams {
    let modulus = Odd::new(n.as_boxed_uint().clone())
        .into_option()
        .expect("the SRP modulus is odd");

    BoxedMontyParams::new(modulus)
}

/// `value mod N`, in Montgomery form.
pub(super) fn field(value: &BigNumber, params: &BoxedMontyParams) -> BoxedMontyForm {
    let reduced = value.as_boxed_uint().rem(params.modulus().as_nz_ref());
    let padded = BoxedUint::from_be_slice(
        &reduced.to_be_bytes_trimmed_vartime(),
        params.bits_precision(),
    )
    .expect("the reduced value fits the modulus precision");

    BoxedMontyForm::new(padded, params)
}

/// The big-endian bytes of a Montgomery-form value.
pub(super) fn field_bytes(value: &BoxedMontyForm) -> Vec<u8> {
    value.retrieve().to_be_bytes_trimmed_vartime().to_vec()
}

/// `value mod modulus == 0`, the RFC 5054 §2.5.4 safeguard.
pub(super) fn is_zero_mod(value: &BigNumber, modulus: &BigNumber) -> bool {
    let nz = NonZero::new(modulus.as_boxed_uint().clone())
        .into_option()
        .expect("the modulus is non-zero");

    value.as_boxed_uint().rem(&nz).is_zero().to_bool()
}

// u = Hash(A, B)
// #[doc(alias = "u")]
// pub type Hash = BigLNumber;
