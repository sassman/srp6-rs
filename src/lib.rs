//! # An safe rust native implementaiton of Secure Remote Password (SRP6) authentication protocol.
//!
//! **NOTE**: Please do only use key length >= 2048 bit in production.
//!           You can do so by using either of
//!           [`Srp6_2048`], [`Srp6_4096`], [`Srp6_6144`], [`Srp6_8192`]
//!
//! ## Usage
//!
//! The example walks one full authentication: the server stores a salt and
//! verifier per user, opens a handshake, and both sides prove each other. The
//! values at the boundary are byte-backed newtypes ([`Salt`], [`Verifier`],
//! [`PublicKey`], [`Proof`], [`StrongSessionKey`]), so no arithmetic detail
//! shows up in the types a caller handles.
//!
//! ```rust
//! use srp6::prelude::*;
//!
//! // signup: the server stores the username, salt and verifier
//! let username = Username::new("alice").expect("valid username");
//! let srp = Srp6_4096::default();
//! let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
//! assert_eq!(salt.as_bytes().len(), 16); // the default; `with_salt` overrides it
//! assert_eq!(verifier.as_bytes().len(), 512);
//!
//! // login: the server opens the handshake from the stored secrets
//! let (handshake, proof_verifier) = srp
//!     .start_handshake(&username, salt, verifier)
//!     .expect("the handshake starts");
//!
//! // the client sends its proof
//! let (proof, strong_proof_verifier) = srp
//!     .calculate_proof(&handshake, &username, "password123")
//!     .expect("the client can prove");
//!
//! // the server verifies the proof and answers with the strong proof M2
//! let strong_proof = srp
//!     .verify_proof(&proof_verifier, &proof)
//!     .expect("the proof verifies");
//!
//! // the client verifies the server; both sides now share the session key K
//! let session_key = srp
//!     .verify_strong_proof(&strong_proof_verifier, &strong_proof)
//!     .expect("the strong proof verifies");
//! assert_eq!(session_key, *strong_proof_verifier.session_key());
//! ```
//!
//! ## Note on key length
//!
//! this crate provides some default keys [preconfigured and aliased][defaults].
//! The modulus prime and generator numbers are taken from [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054).
//!
//! ## Note on hash length
//!
//! The original RFC5054 uses SHA1 as the hash function.
//! This crate uses SHA512 as the default hash function,
//! because SHA1 is considered weak, it is recommended to use newer versions of the SHA family.
//!
//! The hash length is 64 bytes for SHA512 instead of 20 bytes for SHA1.
//! If you really need to use SHA1, you can use the `hash-sha1` feature.
//!
//! ## Further details and domain vocabulary
//! - You can find the documentation of SRP6 [variables in a dedicated module][`protocol_details`].
//! - [RFC2945](https://datatracker.ietf.org/doc/html/rfc2945) that describes in detail the Secure remote password protocol (SRP).
//! - [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054) that describes SRP6 for TLS Authentication
//! - [check out the 2 examples](./examples) that illustrates the srp authentication flow as well

// Modules
pub mod defaults;
pub mod group;
pub mod hash;
pub mod protocol_details;
pub mod rfc_5054_appendix_a;
pub mod rfc_lingo;

mod credentials;
mod error;
mod typed;

#[cfg(test)]
mod golden_vectors;
#[cfg(all(test, feature = "test-rfc-5054-appendix-b"))]
pub mod rfc_5054_appendix_b;
#[cfg(feature = "wow-1-12-1")]
pub mod wow;

// Crate-root re-exports
pub use credentials::*;
pub use defaults::*;
pub use error::Srp6Error;
pub use group::*;
pub use typed::*;

/// encapsulates a [`crate::error::Srp6Error`]
pub type Result<T> = std::result::Result<T, crate::error::Srp6Error>;

pub mod prelude {
    pub use crate::credentials::*;
    pub use crate::defaults::*;
    pub use crate::error::Srp6Error;
    pub use crate::group::*;
    pub use crate::hash::HASH_LENGTH;
    pub use crate::typed::*;
    pub use std::convert::TryInto;
}
