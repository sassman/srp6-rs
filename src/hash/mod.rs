#[cfg(all(feature = "hash-sha1", feature = "hash-sha512"))]
compile_error!("either feature `hash-sha1` or `hash-sha512` is used, not both");

#[cfg(all(not(feature = "hash-sha1"), not(feature = "hash-sha512")))]
compile_error!("either feature `hash-sha1` or `hash-sha512` must be used");

#[cfg(feature = "hash-sha1")]
mod sha1;

#[cfg(feature = "hash-sha512")]
mod sha512;

#[cfg(all(not(feature = "hash-sha512"), feature = "hash-sha1"))]
pub use sha1::{Digest, HashFunc, Update, HASH_LENGTH};
#[cfg(all(feature = "hash-sha512", not(feature = "hash-sha1")))]
pub use sha512::{Digest, HashFunc, Update, HASH_LENGTH};

pub type Hash = [u8; HASH_LENGTH];

/// The interleaved strong session key `K` is two hashes wide.
pub(crate) const STRONG_SESSION_KEY_LENGTH: usize = HASH_LENGTH * 2;
