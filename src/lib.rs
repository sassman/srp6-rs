/*!
An implementation of Secure Remote Password (SRP6) authentication protocol.

**NOTE**: Please do only use key length >= 2048 bit in production. You can do so by using [`Srp6_2048`] or [`Srp6_4096`].

## Usage
The usage example start on the server side.
Client side interaction is marked explicit when needed.

### 1. A new user, welcome Bob

```rust
use srp6::*;

// this is happening on the client,
// the password is never send to the server at any time
let new_username: UsernameRef = "Bob";
let user_password: &ClearTextPassword = "secret-password";

let (salt_s, verifier_v) = Srp6_2048::default().generate_new_user_secrets(
    new_username,
    user_password
);

assert_eq!(salt_s.num_bytes(), Srp6_2048::KEY_LEN);
assert_eq!(verifier_v.num_bytes(), Srp6_2048::KEY_LEN);

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

let srp = Srp6_2048::default();
let (handshake, proof_verifier) = srp.start_handshake(&user);
assert_eq!(handshake.s, user.salt);
assert_eq!(handshake.N, srp.N);
assert_eq!(handshake.g, srp.g);
assert_eq!(handshake.B.num_bytes(), Srp6_2048::KEY_LEN);

// TODO: next step: the client calculates proof

# mod mocked {
#     use srp6::*;
#
#     /// this is a mock
#     /// normally this would come from a user database
#     pub fn lookup_user_details(username: UsernameRef) -> UserDetails {
#         use std::convert::TryInto;
#
#         UserDetails {
#             username: username.to_owned(),
#             salt: "CC927E15A5E5B5F420F26A498F14E98D7DC201DCB4CBF4E8E82320AC092A5C0ADE338D7392F7C23C20DDF08D79E3DF83203759887C779B12C18B840A6AEF40A9FCF4D0103C48A832402B07D882F495BFC66A9D6BAAEADF7FEE5965C8BD89CE09FF4572B73DD44DE610514BE19D58B27E4F57641D093B97834EB1D8EAD5BB2DE61777240566DC00AA906E6E5C674ECE33DAC5887685E5BE3E93322CA426715A9B5EF71DF0790459EA638006DCA52B63B6E49CCD239C7F7F8ED60DEA8A85572FEC53991A339A58C1D35962217B2CE57D63A75CD7CF6DEAECEE050684D34D8B4511778C40F3DBFCCBB22A887BA9EDFA894A4D0B83FEADF919F59776A5E969C3AEF4"
#                 .try_into()
#                 .unwrap(),
#             verifier: "9310C7532A50A7266F5F7D26E93DED88C0600D3CD1B7F16B1B3756D4FBA448E5A7D79E5F516332597E46CB44331B9FACD698D8E821B518A289332165AF8BAD0089421528126432598EE979A83A074141E10A6B625394FB8A3E9FFF0858A89B790895EA23AC75A32B15FAD6EFA5E928762AB3BEA4804E67BC290CAA685DB0A1F138AE7ED8424723302918DBBE454DE10F59039244ACCCD0CABF65923291E29DD4CB189BD718D935FABE31AEEA005BE50410E5FCA68D8F1D163ED7A06C37718B0B06528D08522CB9564F3C915384DF69F69E6FDEDFB59145F8AFB27C54402E0078130FA1C93512653C63FF4CFD772E8A82414C31DA9D3627D63BB56ED482BEF3DF"
#                 .try_into()
#                 .unwrap(),
#         }
#     }
# }
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

# mod mocked {
#     use srp6::*;
#     type Srp6 = Srp6_2048;
#
#     /// this is a mock, nothing you should do on the client side
#     pub fn handshake_from_the_server(username: UsernameRef) -> Handshake<{ Srp6::KEY_LEN }, { Srp6::SALT_LEN }> {
#         let user = lookup_user_details(username);
#         let (handshake, _) = Srp6::default().start_handshake(&user);
#         handshake
#     }
#
#     /// this is a mock
#     /// normally this would come from a user database
#     pub fn lookup_user_details(username: UsernameRef) -> UserDetails {
#         use std::convert::TryInto;
#
#         UserDetails {
#             username: username.to_owned(),
#             salt: "CC927E15A5E5B5F420F26A498F14E98D7DC201DCB4CBF4E8E82320AC092A5C0ADE338D7392F7C23C20DDF08D79E3DF83203759887C779B12C18B840A6AEF40A9FCF4D0103C48A832402B07D882F495BFC66A9D6BAAEADF7FEE5965C8BD89CE09FF4572B73DD44DE610514BE19D58B27E4F57641D093B97834EB1D8EAD5BB2DE61777240566DC00AA906E6E5C674ECE33DAC5887685E5BE3E93322CA426715A9B5EF71DF0790459EA638006DCA52B63B6E49CCD239C7F7F8ED60DEA8A85572FEC53991A339A58C1D35962217B2CE57D63A75CD7CF6DEAECEE050684D34D8B4511778C40F3DBFCCBB22A887BA9EDFA894A4D0B83FEADF919F59776A5E969C3AEF4"
#                 .try_into()
#                 .unwrap(),
#             verifier: "9310C7532A50A7266F5F7D26E93DED88C0600D3CD1B7F16B1B3756D4FBA448E5A7D79E5F516332597E46CB44331B9FACD698D8E821B518A289332165AF8BAD0089421528126432598EE979A83A074141E10A6B625394FB8A3E9FFF0858A89B790895EA23AC75A32B15FAD6EFA5E928762AB3BEA4804E67BC290CAA685DB0A1F138AE7ED8424723302918DBBE454DE10F59039244ACCCD0CABF65923291E29DD4CB189BD718D935FABE31AEEA005BE50410E5FCA68D8F1D163ED7A06C37718B0B06528D08522CB9564F3C915384DF69F69E6FDEDFB59145F8AFB27C54402E0078130FA1C93512653C63FF4CFD772E8A82414C31DA9D3627D63BB56ED482BEF3DF"
#                 .try_into()
#                 .unwrap(),
#         }
#     }
# }
```

### 4. Verify `Proof` from Bob
- The client sends the proof to the server
- The server calculates his version of the Proof and compoares if they match

```rust
// this comes from the server
let username = "Bob";
let handshake = mocked::stored_proof_verifier_from_step_2(username);

# mod mocked {
#     use srp6::*;
#
#     /// this is a mock, nothing you should do on the client side
#     pub fn stored_proof_verifier_from_step_2(username: UsernameRef) -> HandshakeProofVerifier {
#         let user = lookup_user_details(username);
#         let (_, proof_verifier) = Srp6_2048::default().start_handshake(&user);
#         proof_verifier
#     }
#
#     /// this is a mock
#     /// normally this would come from a user database
#     pub fn lookup_user_details(username: UsernameRef) -> UserDetails {
#         use std::convert::TryInto;
#
#         UserDetails {
#             username: username.to_owned(),
#             salt: "CC927E15A5E5B5F420F26A498F14E98D7DC201DCB4CBF4E8E82320AC092A5C0ADE338D7392F7C23C20DDF08D79E3DF83203759887C779B12C18B840A6AEF40A9FCF4D0103C48A832402B07D882F495BFC66A9D6BAAEADF7FEE5965C8BD89CE09FF4572B73DD44DE610514BE19D58B27E4F57641D093B97834EB1D8EAD5BB2DE61777240566DC00AA906E6E5C674ECE33DAC5887685E5BE3E93322CA426715A9B5EF71DF0790459EA638006DCA52B63B6E49CCD239C7F7F8ED60DEA8A85572FEC53991A339A58C1D35962217B2CE57D63A75CD7CF6DEAECEE050684D34D8B4511778C40F3DBFCCBB22A887BA9EDFA894A4D0B83FEADF919F59776A5E969C3AEF4"
#                 .try_into()
#                 .unwrap(),
#             verifier: "9310C7532A50A7266F5F7D26E93DED88C0600D3CD1B7F16B1B3756D4FBA448E5A7D79E5F516332597E46CB44331B9FACD698D8E821B518A289332165AF8BAD0089421528126432598EE979A83A074141E10A6B625394FB8A3E9FFF0858A89B790895EA23AC75A32B15FAD6EFA5E928762AB3BEA4804E67BC290CAA685DB0A1F138AE7ED8424723302918DBBE454DE10F59039244ACCCD0CABF65923291E29DD4CB189BD718D935FABE31AEEA005BE50410E5FCA68D8F1D163ED7A06C37718B0B06528D08522CB9564F3C915384DF69F69E6FDEDFB59145F8AFB27C54402E0078130FA1C93512653C63FF4CFD772E8A82414C31DA9D3627D63BB56ED482BEF3DF"
#                 .try_into()
#                 .unwrap(),
#         }
#     }
# }
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
