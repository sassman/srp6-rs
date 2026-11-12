use crate::error::Srp6Error;
use crate::Result;

/// The salt width [`crate::Srp6::generate_new_user_secrets`] draws, in bytes.
///
/// Opaque so no bare literal can slip in: the reasonable options are the
/// `const`s, anything else must spell out [`SaltBytes::custom`] and pass its
/// bounds check. Set once per [`crate::Srp6`] via [`crate::Srp6::with_salt`];
/// stored and received salts of any length are still accepted as-is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaltBytes(usize);

impl SaltBytes {
    /// The industry norm (bcrypt, RFC 5054 appendix B test vector).
    pub const BYTES_16: SaltBytes = SaltBytes(16);
    /// A conservative step up; the WoW flavour's wire width.
    pub const BYTES_32: SaltBytes = SaltBytes(32);

    /// NIST SP 800-132 floor: a salt below 64 bit invites precomputation.
    const MIN: usize = 8;
    /// RFC 5054 wire cap: `opaque srp_s<1..2^8-1>` cannot carry more.
    const MAX: usize = 255;

    /// Escape hatch for a deliberate, unusual width.
    ///
    /// # Errors
    /// Returns [`Srp6Error::InvalidSaltLength`] outside `8..=255`, so a typo
    /// cannot weaken the salt or break the wire encoding.
    pub fn custom(bytes: usize) -> Result<SaltBytes> {
        if (Self::MIN..=Self::MAX).contains(&bytes) {
            Ok(SaltBytes(bytes))
        } else {
            Err(Srp6Error::InvalidSaltLength {
                given: bytes,
                min: Self::MIN,
                max: Self::MAX,
            })
        }
    }

    pub(crate) fn get(self) -> usize {
        self.0
    }
}
