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
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, ConcatenatingMul, NonZero, Odd,
};

use crate::big_number::BigNumber;
use crate::credentials::{ClearTextPasswordRef, UsernameRef};
use crate::hash::*;
use crate::{error::Srp6Error, Result};
use std::fmt::{Display, Formatter};

/// Refers to a large safe prime called `N` (`N = 2q+1`, where `q` is prime)
#[doc(alias = "N")]
pub type PrimeModulus = BigNumber;

/// Refers to the modulus generator `g`
#[doc(alias = "g")]
pub type Generator = BigNumber;

/// Refers to a User's salt called `s`
#[doc(alias = "s")]
pub type Salt = BigNumber;

/// Refers to a Public shared key called A (user), B (server)
///
/// Unlike the other primitives, [`PublicKey`] is not a plain alias to
/// [`BigNumber`]. It can only be built through [`PublicKey::new`], which
/// enforces the RFC 5054 §2.5.4 safeguard: "abort if \[the\] value ... is 0 mod N".
/// This makes it impossible to hold a degenerate key (0, `N`, or any multiple
/// of `N`) in a value of this type.
#[doc(alias("A", "B"))]
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(BigNumber);

impl PublicKey {
    /// Validates `value` and wraps it into a [`PublicKey`].
    ///
    /// Per [RFC 5054 §2.5.4](https://datatracker.ietf.org/doc/html/rfc5054#section-2.5.4),
    /// a host or client must "abort if \[the received public key\] % N is zero",
    /// since a degenerate key of that shape lets a hostile peer drive the
    /// shared session key to a value it already knows. This constructor is
    /// the only way to obtain a [`PublicKey`], so that guarantee holds for
    /// every value of this type, not just the ones checked right before use.
    pub fn new(value: BigNumber, n: &PrimeModulus) -> Result<Self> {
        if is_zero_mod(&value, n) {
            return Err(Srp6Error::InvalidPublicKey(value.to_vec()));
        }

        Ok(Self(value))
    }

    /// Big-endian bytes, zero-padded to at least `N` bytes.
    /// See [`BigNumber::to_array_pad_zero`].
    pub fn to_array_pad_zero<const N: usize>(&self) -> Vec<u8> {
        self.0.to_array_pad_zero::<N>()
    }

    /// The runtime-length form of [`PublicKey::to_array_pad_zero`].
    pub(crate) fn to_array_pad_zero_len(&self, len: usize) -> Vec<u8> {
        self.0.to_array_pad_zero_len(len)
    }

    /// Big-endian bytes. See [`BigNumber::to_vec`].
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Length of the big-endian encoding, without leading zeroes.
    /// See [`BigNumber::num_bytes`].
    pub fn num_bytes(&self) -> usize {
        self.0.num_bytes()
    }

    /// Access to the inner [`BigNumber`] for arithmetic. Deliberately not a
    /// [`std::ops::Deref`] impl, so the wrapper stays visible wherever the
    /// number is used.
    pub fn as_bignum(&self) -> &BigNumber {
        &self.0
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// Refers to a private secret random number a (user), b (server)
#[doc(alias("a", "b", "x"))]
pub type PrivateKey = BigNumber;

/// Password Verifier is the users secret on the server side
#[doc(alias = "v")]
pub type PasswordVerifier = BigNumber;

/// Refers to a multiplier parameter `k` (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
#[doc(alias = "k")]
pub type MultiplierParameter = BigNumber;

/// Refers to the SessionKey `S`
#[doc(alias = "S")]
pub type SessionKey = BigNumber;
/// Refers to the StrongSessionKey `K`
#[doc(alias = "K")]
pub type StrongSessionKey = BigNumber;

/// Refers to `M` and `M1` Proof of server and client
#[doc(alias("M", "M1"))]
pub type Proof = BigNumber;
/// Refers to `M2` the hash of Proof
#[doc(alias = "M2")]
pub type StrongProof = BigNumber;

/// The Montgomery parameters for the group modulus `N`.
fn monty_params(n: &PrimeModulus) -> BoxedMontyParams {
    let modulus = Odd::new(n.as_boxed_uint().clone())
        .into_option()
        .expect("the SRP modulus is odd");

    BoxedMontyParams::new(modulus)
}

/// `value mod N`, in Montgomery form.
fn field(value: &BigNumber, params: &BoxedMontyParams) -> BoxedMontyForm {
    let reduced = value.as_boxed_uint().rem(params.modulus().as_nz_ref());
    let padded = BoxedUint::from_be_slice(
        &reduced.to_be_bytes_trimmed_vartime(),
        params.bits_precision(),
    )
    .expect("the reduced value fits the modulus precision");

    BoxedMontyForm::new(padded, params)
}

/// The big-endian bytes of a Montgomery-form value.
fn field_bytes(value: &BoxedMontyForm) -> Vec<u8> {
    value.retrieve().to_be_bytes_trimmed_vartime().to_vec()
}

/// `value mod modulus == 0`, the RFC 5054 §2.5.4 safeguard.
fn is_zero_mod(value: &BigNumber, modulus: &BigNumber) -> bool {
    let nz = NonZero::new(modulus.as_boxed_uint().clone())
        .into_option()
        .expect("the modulus is non-zero");

    value.as_boxed_uint().rem(&nz).is_zero().to_bool()
}

// u = Hash(A, B)
// #[doc(alias = "u")]
// pub type Hash = BigLNumber;

/// host version of a session key for a given user
/// S: is the session key of a user
/// u: is the hash of user and server pub keys
///
/// u = H(A, B)
/// S = (Av^u) ^ b
#[allow(non_snake_case)]
pub fn calculate_session_key_S_for_host<const N_BYTE_LEN: usize>(
    N: &PrimeModulus,
    A: &PublicKey,
    B: &PublicKey,
    b: &PrivateKey,
    v: &PasswordVerifier,
) -> Result<SessionKey> {
    // safeguard A % N == 0 should be checked
    // this is now a second line of defense, PublicKey::new() already rejects this at construction
    if is_zero_mod(A.as_bignum(), N) {
        return Err(Srp6Error::InvalidPublicKey(A.to_vec()));
    }

    let params = monty_params(N);
    let a = field(A.as_bignum(), &params);
    let u = calculate_u::<N_BYTE_LEN>(A, B);
    let s = a
        .mul(&field(v, &params).pow(u.as_boxed_uint()))
        .pow(b.as_boxed_uint());

    Ok(SessionKey::from_bytes_be(&field_bytes(&s)))
}

/// client version of the session key calculation, depends on
/// - the users [`PrivateKey`] `x`
/// - the users [`PublicKey`] `A`
/// - the servers [`PublicKey`] `B`
/// - formulas found so far:
///   - `S = (B - (k * g^x)) ^ (a + (u * x)) % N`
///   - `S = (B - (k * v)) ^ (a + (u * x)) % N`
#[allow(non_snake_case)]
#[allow(clippy::many_single_char_names)]
pub fn calculate_session_key_S_for_client<const N_BYTE_LEN: usize>(
    N: &PrimeModulus,
    k: &MultiplierParameter,
    g: &Generator,
    B: &PublicKey,
    A: &PublicKey,
    a: &PrivateKey,
    x: &PrivateKey,
) -> Result<SessionKey> {
    // safeguard B % N == 0
    // this is now a second line of defense, PublicKey::new() already rejects this at construction
    if is_zero_mod(B.as_bignum(), N) {
        return Err(Srp6Error::InvalidPublicKey(B.to_vec()));
    }

    let params = monty_params(N);
    let b = field(B.as_bignum(), &params);
    let u = calculate_u::<N_BYTE_LEN>(A, B);
    let ux = u.as_boxed_uint().concatenating_mul(x.as_boxed_uint());
    let exp = a.as_boxed_uint().concatenating_add(&ux);

    let g_x = field(g, &params).pow(x.as_boxed_uint());
    let k_gx = field(k, &params).mul(&g_x);
    let s = b.sub(&k_gx).pow(&exp);

    Ok(SessionKey::from_bytes_be(&field_bytes(&s)))
}

/// the hash of a session key `S` that is called `K`
/// S: is the session key of a user
/// K: is the hash of S, just not that straight
#[allow(non_snake_case)]
pub fn calculate_session_key_hash_interleave_K<const N_BYTE_LEN: usize>(
    S: &SessionKey,
) -> StrongSessionKey {
    calculate_session_key_hash_interleave_K_len(S, N_BYTE_LEN)
}

/// The runtime-length form of [`calculate_session_key_hash_interleave_K`].
#[allow(non_snake_case)]
pub(crate) fn calculate_session_key_hash_interleave_K_len(
    S: &SessionKey,
    n_bytes: usize,
) -> StrongSessionKey {
    let S = S.to_array_pad_zero_len(n_bytes);

    // take the even bytes out of S
    let n = S.len() / 2;
    let mut half = vec![0; n];
    for (i, Si) in S.iter().step_by(2).enumerate() {
        half[i] = *Si;
    }
    // hash the even portion of S
    let even_half_of_S_hash = HashFunc::new().chain(&half[..n]).finalize();

    // take the odd bytes of S
    for (i, Si) in S.iter().skip(1).step_by(2).enumerate() {
        half[i] = *Si;
    }
    // hash the odd portion of S
    let odd_half_of_S_hash = HashFunc::new().chain(&half[..n]).finalize();

    let mut vK = [0_u8; STRONG_SESSION_KEY_LENGTH];
    for (i, h_Si) in even_half_of_S_hash
        .iter()
        .zip(odd_half_of_S_hash.iter())
        .enumerate()
    {
        vK[i * 2] = *h_Si.0;
        vK[i * 2 + 1] = *h_Si.1;
    }

    StrongSessionKey::from_bytes_be(&vK)
}

#[allow(non_snake_case)]
pub fn calculate_proof_M<const N_BYTE_LEN: usize, const SALT_LENGTH: usize>(
    N: &PrimeModulus,
    g: &Generator,
    I: UsernameRef,
    s: &Salt,
    A: &PublicKey,
    B: &PublicKey,
    K: &StrongSessionKey,
) -> Proof {
    calculate_proof_M_len(N, g, I, s, A, B, K, N_BYTE_LEN, SALT_LENGTH)
}

/// The runtime-length form of [`calculate_proof_M`]. The two lengths are the
/// only addition, which takes it past clippy's argument limit.
#[allow(non_snake_case, clippy::too_many_arguments)]
pub(crate) fn calculate_proof_M_len(
    N: &PrimeModulus,
    g: &Generator,
    I: UsernameRef,
    s: &Salt,
    A: &PublicKey,
    B: &PublicKey,
    K: &StrongSessionKey,
    n_bytes: usize,
    salt_bytes: usize,
) -> Proof {
    let xor_hash: Hash = calculate_hash_N_xor_g_len(N, g, n_bytes);
    let username_hash = HashFunc::new().chain(I.as_bytes()).finalize();

    Proof::from_bytes_be(
        HashFunc::new()
            .chain(xor_hash)
            .chain(username_hash)
            .chain(s.to_array_pad_zero_len(salt_bytes))
            .chain(A.to_array_pad_zero_len(n_bytes))
            .chain(B.to_array_pad_zero_len(n_bytes))
            .chain(K.to_array_pad_zero_len(STRONG_SESSION_KEY_LENGTH))
            .finalize()
            .as_slice(),
    )
}

/// todo(verify): check if padding is needed or not
/// formula: `H(A | M | K)`
#[allow(non_snake_case)]
pub fn calculate_strong_proof_M2<const KEY_LENGTH: usize>(
    A: &PublicKey,
    M: &Proof,
    K: &StrongSessionKey,
) -> StrongProof {
    calculate_strong_proof_M2_len(A, M, K, KEY_LENGTH)
}

/// The runtime-length form of [`calculate_strong_proof_M2`].
#[allow(non_snake_case)]
pub(crate) fn calculate_strong_proof_M2_len(
    A: &PublicKey,
    M: &Proof,
    K: &StrongSessionKey,
    key_bytes: usize,
) -> StrongProof {
    HashFunc::new()
        .chain(A.to_array_pad_zero_len(key_bytes))
        .chain(M.to_array_pad_zero_len(HASH_LENGTH))
        .chain(K.to_array_pad_zero_len(STRONG_SESSION_KEY_LENGTH))
        .into()
}

/// here we hash g and xor it with the hash of N
///
/// ```plain
/// M = H(H(N) xor H(g), H(I), s, A, B, K)
///       `````````````
///                    // this portion is calculated here
/// ```
#[allow(non_snake_case)]
fn calculate_hash_N_xor_g_len(N: &PrimeModulus, g: &Generator, key_bytes: usize) -> Hash {
    let mut h = HashFunc::new()
        .chain(N.to_array_pad_zero_len(key_bytes))
        .finalize();
    let h_g = HashFunc::new().chain(g.to_vec().as_slice()).finalize();
    for (i, v) in h.iter_mut().enumerate() {
        *v ^= h_g[i];
    }

    let H_n_g: Hash = h.into();

    H_n_g
}

/// here we calculate the `PasswordVerifier` called `v` based on `x`
/// **Note**: something that only needs to be done on user pw change, or user creation
/// `x`:  Private key (derived from p and s)
/// `v`:  Password verifier
/// `g`:  A generator modulo N
/// `N`:  A large safe prime (N = 2q+1, where q is prime)
/// formula: `v = g^x % N`
#[allow(non_snake_case)]
pub fn calculate_password_verifier_v(
    N: &PrimeModulus,
    g: &Generator,
    x: &PrivateKey,
) -> PasswordVerifier {
    let params = monty_params(N);
    let v = field(g, &params).pow(x.as_boxed_uint());

    PasswordVerifier::from_bytes_be(&field_bytes(&v))
}

/// `u` is the hash of host's [`PublicKey`][`crate::rfc_lingo::A`] and client's [`PublicKey`][`crate::rfc_lingo::B`]
/// formula: `H(PAD(A) | PAD(B))`
/// The Padding is based on the key length, e.g. if N is 1024 bit, the padding is 128 bytes
#[allow(non_snake_case)]
pub fn calculate_u<const N_BYTE_LEN: usize>(A: &PublicKey, B: &PublicKey) -> BigNumber {
    calculate_u_len(A, B, N_BYTE_LEN)
}

/// The runtime-length form of [`calculate_u`].
#[allow(non_snake_case)]
pub(crate) fn calculate_u_len(A: &PublicKey, B: &PublicKey, n_bytes: usize) -> BigNumber {
    hash_w_pad_len(A.as_bignum(), B.as_bignum(), n_bytes)
}

/// [`A`][`crate::rfc_lingo::A`] is the [`PublicKey`] of the client
/// formula: `A = g^a % N`
///
/// # Errors
/// [`Srp6Error::InvalidPublicKey`] if the result is `0 mod N`. For a prime
/// `N` and a generator `g < N` that cannot happen, but `N` is supplied by
/// the caller and never proven prime: with a degenerate group such as
/// `N = 4, g = 2, a = 2` the result is 0. Constructing through
/// [`PublicKey::new`] keeps that a `Result` rather than a panic.
#[allow(non_snake_case)]
pub fn calculate_pubkey_A(N: &PrimeModulus, g: &Generator, a: &PrivateKey) -> Result<PublicKey> {
    let params = monty_params(N);
    let public = field(g, &params).pow(a.as_boxed_uint());

    PublicKey::new(BigNumber::from_bytes_be(&field_bytes(&public)), N)
}

/// [`PublicKey`][`crate::rfc_lingo::B`] is the hosts public key
/// `B = kv + g^b`
///
/// # Errors
/// [`Srp6Error::InvalidPublicKey`] if the result is `0 mod N`. Unlike
/// [`calculate_pubkey_A`], `B` is a sum reduced mod `N`, so `k*v = -g^b`
/// lands on 0 even for a well formed group. It is vanishingly unlikely,
/// and the client rejects such a `B` on receipt anyway, but the host
/// should not hand one out: draw a fresh `b` and call again.
#[allow(non_snake_case)]
pub fn calculate_pubkey_B(
    N: &PrimeModulus,
    k: &MultiplierParameter,
    g: &Generator,
    v: &PasswordVerifier,
    b: &PrivateKey,
) -> Result<PublicKey> {
    let params = monty_params(N);
    let public = field(k, &params)
        .mul(&field(v, &params))
        .add(&field(g, &params).pow(b.as_boxed_uint()));

    PublicKey::new(BigNumber::from_bytes_be(&field_bytes(&public)), N)
}

/// `x` is the users private key (only they know)
///
/// I:  Username                (validated, and uppercased for WoW, by [`Username::new`])
/// p:  Cleartext Password      (is uppercased for WoW)
/// s:  User's salt
/// x:  Private key             (derived from p and s)
/// ph = H(I, ':', p)           (':' is a string literal)
/// x = H(s, ph)                (s is chosen randomly)
#[allow(non_snake_case)]
#[allow(dead_code)]
pub fn calculate_private_key_x(I: UsernameRef, p: ClearTextPasswordRef, s: &Salt) -> PrivateKey {
    let ph = calculate_p_hash(I, p);

    PrivateKey::from_bytes_be(
        HashFunc::new()
            .chain(s.to_vec())
            .chain(ph)
            .finalize()
            .as_slice(),
    )
}

/// hashes the user and the password (used for client private key `x`)
/// formula: `H(I ":" p)`
#[allow(non_snake_case)]
pub fn calculate_p_hash(I: UsernameRef, p: ClearTextPasswordRef) -> Hash {
    // WoW's 1.12.1 client also uppercases the password before hashing.
    // Username normalisation (uppercasing) now happens once, at
    // construction time, in `Username::new`, so it must not be
    // repeated here. The password stays a plain `&str` though: it is not
    // wrapped in its own newtype because a password should be zeroised
    // after use rather than retained in a stored type, so its WoW-specific
    // uppercasing still has to happen here, at the point of use.
    #[cfg(feature = "wow-1-12-1")]
    let p: String = p.to_uppercase();
    #[cfg(not(feature = "wow-1-12-1"))]
    let p: &str = p;

    HashFunc::new()
        .chain(I.as_bytes())
        .chain(":".as_bytes())
        .chain(p.as_bytes())
        .finalize()
        .into()
}

/// `k = H(N | PAD(g))` (k = 3 for legacy SRP-6)
#[allow(non_snake_case)]
#[cfg(not(feature = "wow-1-12-1"))]
pub fn calculate_k<const KEY_LENGTH: usize>(
    N: &PrimeModulus,
    g: &Generator,
) -> MultiplierParameter {
    HashFunc::new()
        .chain(N.to_vec().as_slice())
        .chain(g.to_array_pad_zero::<KEY_LENGTH>())
        .into()
}

/// `k = H(N | PAD(g))` (k = 3 for legacy SRP-6)
#[cfg(feature = "wow-1-12-1")]
pub fn calculate_k<const KEY_LENGTH: usize>(
    _: &PrimeModulus,
    _: &Generator,
) -> MultiplierParameter {
    MultiplierParameter::from(3)
}

/// [`PrivateKey`] `a` or `b` is in fact just a big (positive) random number
pub fn generate_private_key<const KEY_LENGTH: usize>() -> PrivateKey {
    PrivateKey::new_rand(KEY_LENGTH)
}
