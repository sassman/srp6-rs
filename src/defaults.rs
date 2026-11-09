//!
//! Default prime modulus and generator numbers taken from [RFC5054 Appendix A],
//! so they can be treated as vetted and safe.
//!
//! ## Usage:
//!
//! ```rust
//! use srp6::prelude::{Srp6_4096, Username};
//!
//! let bob = Username::new("Bob").expect("valid username");
//! let srp = Srp6_4096::default();
//! let (_salt_s, _verifier_v) = srp.generate_new_user_secrets(&bob, "secret-password");
//! ```
//!
//! [RFC5054 Appendix A]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A

#[rustfmt::skip]
pub use crate::rfc_5054_appendix_a::{
    // The 2048-bit group: `N_BYTES` and `SALT_BYTES` are both 2048 bit / 256 byte.
    group_2048_bit::Srp6_2048,
    // The 3072-bit group: `N_BYTES` and `SALT_BYTES` are both 3072 bit / 384 byte.
    group_3072_bit::Srp6_3072,
    // The 4096-bit group: `N_BYTES` and `SALT_BYTES` are both 4096 bit / 512 byte.
    group_4096_bit::Srp6_4096,
    // The 6144-bit group: `N_BYTES` and `SALT_BYTES` are both 6144 bit / 768 byte.
    group_6144_bit::Srp6_6144,
    // The 8192-bit group: `N_BYTES` and `SALT_BYTES` are both 8192 bit / 1024 byte.
    group_8192_bit::Srp6_8192,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_ensure_key_lengths_are_as_expected() {
        assert_eq!(Srp6_2048::default().n_bytes(), 2048 / 8);
        assert_eq!(Srp6_3072::default().n_bytes(), 3072 / 8);
    }
}
