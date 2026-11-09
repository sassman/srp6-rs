/*!
This module defines a list of all primitive types and functions
needed to express the meaning of certain variables better.

For instance in [RFC2945] the big prime number that acts
as the modulus in every mathematical power operation is called `N`.

In order to increase readability the type of `N` is
an alias to [`BigNumber`] that aims to express the meaning,
so [`PrimeModulus`] is same as `N` which is a [`BigNumber`].

This scheme is applied for all variables used in the calculus.

[RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
*/
// The non-len calculus is the golden and appendix-B oracle; the handshake calls the _len forms.
#![allow(dead_code, unused_imports)]

use crate::big_number::BigNumber;

mod montgomery;
mod multiplier;
mod private_key;
mod proof;
mod public_key;
mod scrambler;
mod session_key;
mod verifier;

pub(crate) use multiplier::*;
pub(crate) use private_key::*;
pub(crate) use proof::*;
pub(crate) use public_key::*;
pub(crate) use scrambler::*;
pub(crate) use session_key::*;
pub(crate) use verifier::*;

/// Refers to a large safe prime called `N` (`N = 2q+1`, where `q` is prime)
#[doc(alias = "N")]
pub(crate) type PrimeModulus = BigNumber;

/// Refers to the modulus generator `g`
#[doc(alias = "g")]
pub(crate) type Generator = BigNumber;

/// Refers to a User's salt called `s`
#[doc(alias = "s")]
pub(crate) type Salt = BigNumber;

/// Refers to a private secret random number a (user), b (server)
#[doc(alias("a", "b", "x"))]
pub(crate) type PrivateKey = BigNumber;

/// Password Verifier is the users secret on the server side
#[doc(alias = "v")]
pub(crate) type PasswordVerifier = BigNumber;

/// Refers to a multiplier parameter `k` (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
#[doc(alias = "k")]
pub(crate) type MultiplierParameter = BigNumber;

/// Refers to the SessionKey `S`
#[doc(alias = "S")]
pub(crate) type SessionKey = BigNumber;
/// Refers to the StrongSessionKey `K`
#[doc(alias = "K")]
pub(crate) type StrongSessionKey = BigNumber;

/// Refers to `M` and `M1` Proof of server and client
#[doc(alias("M", "M1"))]
pub(crate) type Proof = BigNumber;
/// Refers to `M2` the hash of Proof
#[doc(alias = "M2")]
pub(crate) type StrongProof = BigNumber;
