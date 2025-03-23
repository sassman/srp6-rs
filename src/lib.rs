//!
//! # An implementation of Secure Remote Password (SRP6) authentication protocol.
//!
//! **NOTE**: Please do only use key length >= 2048 bit in production.
//!           You can do so by using [`Srp6_2048`] or [`Srp6_4096`] or related.
//!
//! ## Usage
//!
//! The usage example start on the server side.
//! Client side interaction is marked explicit when needed.
//!
//! ### 1. A new user, welcome Alice
//!
//! ```rust
//! use srp6::prelude::*;
//!
//! // this is happening on the client,
//! // the password is never send to the server at any time
//! let new_username = Username::from("alice");
//! let user_password = ClearTextPassword::from("password123");
//!
//! let (salt_s, verifier_v) = Srp6_4096::default()
//!     .generate_new_user_secrets(
//!         &new_username,
//!         &user_password
//!     );
//!
//! assert_eq!(salt_s.num_bytes(), Srp6_4096::KEY_LEN);
//! assert_eq!(verifier_v.num_bytes(), Srp6_4096::KEY_LEN);
//!
//! // The server needs to persist,
//! // `new_username`, `salt_s` and `verifier_v` in a user database / pw file
//! ```
//! **NOTE:** the password of the user will not be stored!
//!
//! **NOTE2:** the salt and verifier will never be the same, they have a random component to it
//!
//! ### 2. A session [`Handshake`] for Alice
//!
//! On the server side (when alice is already registered)
//!
//! - when a user/client connects they would send their [`Username`] first
//! - with the username the server will lookup their [`Salt`] and [`PasswordVerifier`] from a user database or pw file
//! - the server starts the authentication process with a [`Handshake`] send to the client
//! - the server keeps a [`HandshakeProofVerifier`] for the user in order to verify the proof he will get from the client later on
//!
//! ```rust
//! use srp6::prelude::*;
//! use srp6::doc_test_mocks as mocks;
//!
//! // the username is sent by the client
//! let user = mocks::lookup_user_details("alice");
//!
//! // the server starts the handshake
//! let srp = Srp6_4096::default();
//! let (handshake, proof_verifier) = srp.start_handshake(&user);
//!
//! assert_eq!(handshake.s, user.salt);
//! assert_eq!(handshake.N, srp.N);
//! assert_eq!(handshake.g, srp.g);
//! assert_eq!(handshake.B.num_bytes(), Srp6_4096::KEY_LEN);
//!
//! // send `handshake` to the client
//! // keep `proof_verifier` for later in a session or cache
//! ```
//!
//! ### 3. A [`Proof`] that Alice is Alice
//!
//! - with the handshake, alice needs to create [`Proof`] that she is who she says she is
//! - this [`Proof`] and her [`PublicKey`] will be sent to the server where it is verified
//!
//! ```rust
//! use srp6::prelude::*;
//! use srp6::doc_test_mocks as mocks;
//!
//! // this is entered by the user on the client (none is sent to the server)
//! let username = "alice";
//! let password = "password123";
//!
//! // this comes from the server
//! let handshake = mocks::handshake_from_the_server(username);
//!
//! // the final proof calculation
//! let (proof, strong_proof_verifier) = handshake
//!     .calculate_proof(username, password)
//!     .unwrap();
//!
//! // send this `proof` to the server
//! // `strong_proof_verifier` is kept for the final verification
//! ```
//!
//! ### 4. Verify [`Proof`] from Alice
//!
//! - The client sends the proof ([`HandshakeProof`]) to the server
//! - The server calculates their version of the Proof and compoares if they match
//! - On Success both parties have calculated a strong proof ([`StrongProof`] M2) and a session key ([`StrongSessionKey`] K)
//!
//! ```rust
//! use srp6::prelude::*;
//! use srp6::doc_test_mocks as mocks;
//!
//! // this comes from the server
//! let username = "alice";
//! let proof_verifier = mocks::stored_proof_verifier_from_step_2(username);
//! let proof_from_alice = mocks::alice_proof();
//!
//! // the server verifies the proof from alice
//! let (strong_proof, session_key_server) = proof_verifier
//!     .verify_proof(&proof_from_alice)
//!     .expect("proof was invalid");
//!
//! // `strong_proof` is sent back to alice
//! ```
//!
//! ### 5. Alice verifies the server
//!
//! - The client receivs the strong proof ([`StrongProof`] K) from the server
//! - Alice calculates their own strong proof and verifies the both match
//! - On Success both parties have verified each other and have a shared strong proof ([`StrongProof`] M2) and a session key ([`StrongSessionKey`] K)
//!
//! ```rust
//! use srp6::prelude::*;
//! use srp6::doc_test_mocks as mocks;
//!
//! // see the previous step..
//! let strong_proof_verifier = mocks::strong_proof_verifier_from_step_3();
//! let strong_proof = mocks::strong_proof_from_the_server();
//!
//! // alice verifies the proof from the server
//! strong_proof_verifier
//!     .verify_strong_proof(&strong_proof)
//!     .expect("strong proof was invalid");
//! ```
//!
//! ## Note on key length
//!
//! this crate provides some default keys [preconfigured and aliased][defaults].
//! The modulus prime and genrator numbers are taken from [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054).
//!
//! ## Note on hash length
//!
//! The original RFC5054 uses SHA1 as the hash function. This crate uses SHA512 as the default hash function. Because SHA1 is considered weak, it is recommended to use newer versions of the SHA family. The hash length is 64 bytes for SHA512 instead of 20 bytes for SHA1. If you really need to use SHA1, you can use the `dangerous` feature.
//!
//! ## Further details and domain vocabolary
//! - You can find the documentation of SRP6 [variables in a dedicated module][`protocol_details`].
//! - [RFC2945](https://datatracker.ietf.org/doc/html/rfc2945) that describes in detail the Secure remote password protocol (SRP).
//! - [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054) that describes SRP6 for TLS Authentication
//! - [check out the 2 examples](./examples) that illustrates the srp authentication flow as well

pub mod defaults;
pub mod hash;
pub mod protocol_details;
pub mod rfc_lingo;
pub mod prelude {
    pub use crate::api::host::*;
    pub use crate::api::user::*;
    pub use crate::big_number::BigNumber;
    pub use crate::defaults::*;
    pub use crate::error::Srp6Error;
    pub use crate::hash::HASH_LENGTH;
    pub use crate::primitives::*;
    pub use std::convert::TryInto;
}
#[cfg(feature = "dangerous")]
pub mod dangerous;
pub mod rfc_5054_appendix_a;
#[cfg(all(test, feature = "test-rfc-5054-appendix-b"))]
pub mod rfc_5054_appendix_b;

// #[cfg(all(doctest, feature = "doc-test-mocks"))]
#[cfg(doctest)]
pub mod doc_test_mocks;

mod api;
mod big_number;
mod error;
mod primitives;

// // TODO: remove this, in favor of the prelude module
// pub use api::host::*;
// pub use api::user::*;
// pub use defaults::*;
// pub use primitives::{
//     ClearTextPassword, Generator, MultiplierParameter, PasswordVerifier, PrimeModulus, PrivateKey,
//     Proof, PublicKey, Salt, SessionKey, StrongProof, StrongSessionKey, UserCredentials,
//     UserSecrets, Username, UsernameRef,
// };
// pub use std::convert::TryInto;

/// encapsulates a [`crate::error::Srp6Error`]
pub type Result<T> = std::result::Result<T, crate::error::Srp6Error>;

pub use api::host::*;
pub use api::user::*;
pub use defaults::*;
pub use primitives::*;
