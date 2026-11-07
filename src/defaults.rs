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

use crate::group::{Group2048, Group3072, Group4096, Group6144, Group8192};

/// The 2048-bit group: [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and
/// [`Salt`][crate::primitives::Salt] `s` are both 2048 bit / 256 byte.
pub type Srp6_2048 = crate::Srp6<Group2048>;

/// The 3072-bit group: `N` and `s` are both 3072 bit / 384 byte.
pub type Srp6_3072 = crate::Srp6<Group3072>;

/// The 4096-bit group: `N` and `s` are both 4096 bit / 512 byte.
pub type Srp6_4096 = crate::Srp6<Group4096>;

/// The 6144-bit group: `N` and `s` are both 6144 bit / 768 byte.
pub type Srp6_6144 = crate::Srp6<Group6144>;

/// The 8192-bit group: `N` and `s` are both 8192 bit / 1024 byte.
pub type Srp6_8192 = crate::Srp6<Group8192>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;

    #[test]
    fn should_ensure_key_lengths_are_as_expected() {
        assert_eq!(Srp6_2048::default().group.modulus_bytes().len(), 2048 / 8);
        assert_eq!(Srp6_3072::default().group.modulus_bytes().len(), 3072 / 8);
    }
}
