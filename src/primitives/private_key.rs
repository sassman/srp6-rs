use super::{PrivateKey, Salt};
use crate::credentials::{ClearTextPasswordRef, UsernameRef};
use crate::hash::*;

/// `x` is the users private key (only they know)
///
/// I:  Username                (validated, and uppercased for WoW, by [`Username::new`])
/// p:  Cleartext Password      (is uppercased for WoW)
/// s:  User's salt
/// x:  Private key             (derived from p and s)
/// ph = H(I, ':', p)           (':' is a string literal)
/// x = H(s, ph)                (s is chosen randomly)
#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn calculate_private_key_x(I: UsernameRef, p: ClearTextPasswordRef, s: &Salt) -> PrivateKey {
    let ph = calculate_p_hash(I, p);

    PrivateKey::from_bytes_be(
        HashFunc::new()
            .chain(s.to_vec())
            .chain(ph)
            .finalize()
            .as_slice(),
    )
}

/// hashes the user and the password (used for client private key `x`)
/// formula: `H(I ":" p)`
#[allow(non_snake_case)]
pub fn calculate_p_hash(I: UsernameRef, p: ClearTextPasswordRef) -> Hash {
    // WoW's 1.12.1 client also uppercases the password before hashing.
    // Username normalisation (uppercasing) now happens once, at
    // construction time, in `Username::new`, so it must not be
    // repeated here. The password stays a plain `&str` though: it is not
    // wrapped in its own newtype because a password should be zeroised
    // after use rather than retained in a stored type, so its WoW-specific
    // uppercasing still has to happen here, at the point of use.
    #[cfg(feature = "wow-1-12-1")]
    let p: String = p.to_uppercase();
    #[cfg(not(feature = "wow-1-12-1"))]
    let p: &str = p;

    HashFunc::new()
        .chain(I.as_bytes())
        .chain(":".as_bytes())
        .chain(p.as_bytes())
        .finalize()
        .into()
}
