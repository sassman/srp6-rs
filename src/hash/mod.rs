#[cfg(all(feature = "hash-sha1", feature = "hash-sha512"))]
compile_error!("either feature `hash-sha1` or `hash-sha512` is used, not both");

#[cfg(all(not(feature = "hash-sha1"), not(feature = "hash-sha512")))]
compile_error!("either feature `hash-sha1` or `hash-sha512` must be used");

#[cfg(feature = "hash-sha1")]
mod sha1;
#[cfg(feature = "hash-sha1")]
pub use sha1::*;

#[cfg(feature = "hash-sha512")]
mod sha512;
#[cfg(feature = "hash-sha512")]
pub use sha512::*;

pub type Hash = [u8; HASH_LENGTH];
