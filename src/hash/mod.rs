//! The hash is a per-instance type parameter, not a crate-wide feature, so a
//! single binary can run SHA-1 and SHA-512 side by side on different `Srp6`
//! instances. `digest` is re-exported through `sha2` so every consumer shares the
//! exact trait version the hashers were built against.

use std::convert::TryFrom;

pub use sha2::digest::{self, Digest, Output, Update};

/// The default hash: SHA-512. `Srp6<G>` uses it unless a consumer names another.
pub use sha2::Sha512 as DefaultHash;

/// SHA-1, for the legacy WoW 1.12.1 flavour and the RFC 5054 appendix B vectors.
#[cfg(feature = "hash-sha1")]
pub use sha1::Sha1;

/// The strong session key `K` is two hashes wide.
pub(crate) fn strong_session_key_len<H: Digest>() -> usize {
    <H as Digest>::output_size() * 2
}

mod sealed {
    pub trait Sealed {}
}

/// The hashes srp6 supports, each naming the fixed widths its values occupy: a
/// proof is one digest wide and the session key two. Stable Rust cannot size an
/// array by `2 * H::output_size()`, so each hash donates the array types here.
///
/// Sealed: only the vetted hashes implement it, and [`crate::Srp6`] runs on no
/// other. That is also why a caller can take [`crate::Proof::as_array`] and
/// [`crate::StrongSessionKey::as_array`] without a fallible length check.
pub trait SrpHash: Digest + sealed::Sealed {
    /// An `M1`/`M2` proof as a fixed array: one digest wide.
    type ProofBytes: AsRef<[u8]> + Copy + for<'a> TryFrom<&'a [u8]>;
    /// The strong session key `K` as a fixed array: two digests wide.
    type SessionKey: AsRef<[u8]> + Copy + for<'a> TryFrom<&'a [u8]>;
}

impl sealed::Sealed for DefaultHash {}
impl SrpHash for DefaultHash {
    type ProofBytes = [u8; 64];
    type SessionKey = [u8; 128];
}

#[cfg(feature = "hash-sha1")]
impl sealed::Sealed for Sha1 {}
#[cfg(feature = "hash-sha1")]
impl SrpHash for Sha1 {
    type ProofBytes = [u8; 20];
    type SessionKey = [u8; 40];
}

/// A hash the handshake of group `G` can run on.
///
/// The pairing is part of the type so a mismatch does not compile. A group's
/// exponent is sized for its flavour: the 256-bit WoW group has room for SHA-1's
/// `u * x` and not for SHA-512's, where the arithmetic would overflow.
pub trait HashFor<G: crate::group::Group>: SrpHash {}

impl<G: crate::group::RfcGroup> HashFor<G> for DefaultHash {}

#[cfg(feature = "hash-sha1")]
impl<G: crate::group::RfcGroup> HashFor<G> for Sha1 {}

#[cfg(feature = "wow-1-12-1")]
impl HashFor<crate::group::GroupWow> for Sha1 {}
