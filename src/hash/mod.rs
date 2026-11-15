//! The hash is a per-instance type parameter, not a crate-wide feature, so a
//! single binary can run SHA-1 and SHA-512 side by side on different `Srp6`
//! instances. `digest` is re-exported through `sha2` so every consumer shares the
//! exact trait version the hashers were built against.

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
