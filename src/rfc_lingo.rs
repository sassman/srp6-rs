/// This module exposes the protocol types in the lingo of the RFC.
/// For example
///  - `Username` is referred to as `I`
///  - `ClearTextPassword` is referred to as `P`
///  - `Salt` is referred to as `s`
use crate::primitives::*;

pub type N = PrimeModulus;

#[allow(non_camel_case_types)]
pub type g = Generator;

pub type A = PublicKey;

pub type B = PublicKey;

#[allow(non_camel_case_types)]
pub type a = PrivateKey;

#[allow(non_camel_case_types)]
pub type b = PrivateKey;

#[allow(non_camel_case_types)]
pub type x = PrivateKey;

#[allow(non_camel_case_types)]
pub type v = PasswordVerifier;

#[allow(non_camel_case_types)]
pub type k = MultiplierParameter;

pub type S = SessionKey;
pub type K = StrongSessionKey;

pub type M1 = Proof;
pub type M = Proof;

pub type M2 = StrongProof;

pub type I = Username;
pub type P = ClearTextPassword;
