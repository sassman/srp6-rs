/*!
An implementation of Secure Remote Password (SRP6) authentication protocol.

## Usage
The usage example start on the server side.
Client side interaction is marked explicit when needed.

### 1. A new user, welcome Bob

```rust
use srp6::*;

// this is send by the client
let new_username: UsernameRef = "Bob";
let user_password: &ClearTextPassword = "secret-password";

let (salt_s, verifier_v) = Srp6_256::default().generate_new_user_secrets(
    new_username,
    user_password
);

assert_eq!(salt_s.num_bytes(), 256 / 8);
assert_eq!(verifier_v.num_bytes(), 256 / 8);

// The server needs to persist new_username, salt_s and verifier_v in a user database / pw file
```
**NOTE:** the password of the user will not be stored!

**NOTE2:** the salt and verifier will never be the same, they have a random component to it

### 2. A session handshake for Bob
On the server side
- when a user/client connects they would send their [`Username`] first
- with the username the server will lookup their [`Salt`] and [`PasswordVerifier`] from a user database or pw file
- with this data the server would start the authentication with a [`Handshake`] send to the client
- the server would also keep a [`HandshakeProofVerifier`] for this user in order to verify the proof he will get from the client
```rust
use srp6::*;

// the username is sent by the client
let user = mocked::lookup_user_details("Bob");

let srp = Srp6_256::default();
let (handshake, proof_verifier) = srp.start_handshake(&user);
assert_eq!(handshake.s, user.salt);
assert_eq!(handshake.N, srp.N);
assert_eq!(handshake.g, srp.g);
assert_eq!(handshake.B.num_bytes(), 256 / 8);

// TODO: next step: the client calculates proof

mod mocked {
    use srp6::*;

    /// this is a mock
    /// normally this would come from a user database
    pub fn lookup_user_details(username: UsernameRef) -> UserDetails {
        use std::convert::TryInto;

        UserDetails {
            username: username.to_owned(),
            salt: "C7005DA4B7FA6F1B1C75946A74BCDBA48322866E648BB69BA904337993C69591"
                .try_into()
                .unwrap(),
            verifier: "4B0F2ACB3E6023EFE3088DB8F1EAE0C6972622400E4A0406C577C14080E58CBF"
                .try_into()
                .unwrap(),
        }
    }
}
```

### 3. A `Proof` that Bob is Bob
- with the handshake, Bob needs to create [`Proof`] that he is Bob
- this [`Proof`] and his [`PublicKey`] will be sent to the server where it is verified

```rust
use srp6::*;

// from step 1.
let new_username: UsernameRef = "Bob";
let user_password: &ClearTextPassword = "secret-password";
let srp = Srp6_256::default();
let (salt_s, verifier_v) = srp.generate_new_user_secrets(
    new_username,
    user_password
);
// from step 2.
// let handshake = srp.new_handshake(&salt, &verifier);

// this is send by the client
// let proof: Proof = proof_is_send_by_the_client();
// let public_key: PublicKey = public_key_is_send_by_the_client();

// let srp = Srp6_256::default();

```

## Note on key length
this crate provides some default keys [preconfigured and aliased][defaults].
The modulus prime and genrator numbers are taken from [RFC5054].

## Further details and domain vocabolary
- You can find the documentation of SRP6 [variables in a dedicated module][`protocol_details`].
- [RFC2945](https://datatracker.ietf.org/doc/html/rfc2945) that describes in detail the Secure remote password protocol (SRP).
- [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054) that describes SRP6 for TLS Authentication
- [check out the 2 examples](./examples) that illustrates the srp authentication flow as well
*/
use thiserror::Error;

// public exports
pub mod defaults;
pub mod protocol_details;

// internally available
pub(crate) mod primitives;

mod api;
mod big_number;
mod hash;

pub use api::host::*;
pub use defaults::*;
pub use primitives::{
    ClearTextPassword, Generator, MultiplierParameter, PasswordVerifier, PrimeModulus, PrivateKey,
    Proof, PublicKey, Salt, SessionKey, StrongProof, StrongSessionKey, UserCredentials,
    UserDetails, Username, UsernameRef,
};

/// encapsulates a [`Srp6Error`]
pub type Result<T> = std::result::Result<T, Srp6Error>;

#[derive(Error, Debug, PartialEq)]
pub enum Srp6Error {
    #[error(
        "The provided key length ({given:?} byte) does not match the expected ({expected:?} byte)"
    )]
    KeyLengthMismatch { given: usize, expected: usize },
    #[error("The provided proof is invalid")]
    InvalidProof(Proof),
    #[error("The provided public key is invalid")]
    InvalidPublicKey(PublicKey),
}
