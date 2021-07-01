/*!
An implementation of Secure Remote Password (SRP6) authentication protocol.

## Usage
The usage example start on the server side.
Client side interaction is marked explicit when needed.

### 1. A new user, welcome Bob

```rust
use srp6::*;

// this is happening on the client, the password is never send
// to the server at any time
let new_username: UsernameRef = "Bob";
let user_password: &ClearTextPassword = "secret-password";

let (salt_s, verifier_v) = Srp6_256::default().generate_new_user_secrets(
    new_username,
    user_password
);

assert_eq!(salt_s.num_bytes(), 256 / 8);
assert_eq!(verifier_v.num_bytes(), 256 / 8);

// The server needs to persist,
// `new_username`, `salt_s` and `verifier_v` in a user database / pw file
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

// this is entered by the user
let username = "Bob";
let bobs_password: &ClearTextPassword = "secret-password";

// this comes from the server
let handshake = mocked::handshake_from_the_server(username);

// the final proof calculation
let (proof, strong_proof_verifier) = handshake
    .calculate_proof(username, bobs_password)
    .unwrap();

// `proof` send this proof to the server
// `strong_proof_verifier` is kept for the final verification

mod mocked {
    use srp6::*;

    /// this is a mock, nothing you should do on the client side
    pub fn handshake_from_the_server(username: UsernameRef) -> Handshake<32, 32> {
        let user = lookup_user_details(username);
        let (handshake, _) = Srp6_256::default().start_handshake(&user);
        handshake
    }

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

### 4. Verify `Proof` from Bob
- The client sends the proof to the server
- The server calculates his version of the Proof and compoares if they match

```rust

// this comes from the server
let username = "Bob";
let handshake = mocked::stored_proof_verifier_from_step_2(username);

mod mocked {
    use srp6::*;

    /// this is a mock, nothing you should do on the client side
    pub fn stored_proof_verifier_from_step_2(username: UsernameRef) -> HandshakeProofVerifier {
        let user = lookup_user_details(username);
        let (_, proof_verifier) = Srp6_256::default().start_handshake(&user);
        proof_verifier
    }

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

## Note on key length
this crate provides some default keys [preconfigured and aliased][defaults].
The modulus prime and genrator numbers are taken from [RFC5054].

## Further details and domain vocabolary
- You can find the documentation of SRP6 [variables in a dedicated module][`protocol_details`].
- [RFC2945](https://datatracker.ietf.org/doc/html/rfc2945) that describes in detail the Secure remote password protocol (SRP).
- [RFC5054] that describes SRP6 for TLS Authentication
- [check out the 2 examples](./examples) that illustrates the srp authentication flow as well

[RFC5054]: (https://datatracker.ietf.org/doc/html/rfc5054)
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
pub use api::user::*;
pub use defaults::*;
pub use primitives::{
    ClearTextPassword, Generator, MultiplierParameter, PasswordVerifier, PrimeModulus, PrivateKey,
    Proof, PublicKey, Salt, SessionKey, StrongProof, StrongSessionKey, UserCredentials,
    UserDetails, Username, UsernameRef,
};
pub use std::convert::TryInto;

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

    #[error("The provided strong proof is invalid")]
    InvalidStrongProof(StrongProof),

    #[error("The provided public key is invalid")]
    InvalidPublicKey(PublicKey),
}
