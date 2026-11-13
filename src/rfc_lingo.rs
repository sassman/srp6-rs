/// This module exposes the protocol types in the lingo of the RFC.
/// For example
///  - `Username` is referred to as `I`
///  - `ClearTextPassword` is referred to as `P`
///  - `Salt` is referred to as `s`
///
/// Each alias names the typed handshake type; `a`, `b`, `x`, `u` and `S` stay
/// private, so they have no alias.
use crate::{
    ClearTextPassword, FieldElement, Proof, PublicKey, Salt, StrongSessionKey, Username, Verifier,
};

/// The prime modulus `N` is carried by the group type, not by a number.
pub type N<G> = G;

/// The generator `g` of the group.
#[allow(non_camel_case_types)]
pub type g<G> = FieldElement<G>;

pub type A<G> = PublicKey<G>;

pub type B<G> = PublicKey<G>;

#[allow(non_camel_case_types)]
pub type v<G> = Verifier<G>;

/// The multiplier parameter `k`.
#[allow(non_camel_case_types)]
pub type k<G> = FieldElement<G>;

pub type K = StrongSessionKey;

pub type M = Proof;

pub type M1 = Proof;

pub type M2 = Proof;

pub type I = Username;

pub type P = ClearTextPassword;

#[allow(non_camel_case_types)]
pub type s = Salt;
