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
use serde::{Deserialize, Serialize};

use crate::big_number::{BigNumber, BigNumberError, Zero};
use crate::hash::*;
use crate::{error::Srp6Error, Result};
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use thiserror::Error;

const STRONG_SESSION_KEY_LENGTH: usize = HASH_LENGTH * 2;

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
///
/// See also [`RawPublicKey`], the unvalidated wire counterpart used for
/// (de)serialization.
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
        if (&value % n).is_zero() {
            return Err(Srp6Error::InvalidPublicKey(RawPublicKey(value)));
        }

        Ok(Self(value))
    }

    /// Big-endian bytes, zero-padded to at least `N` bytes.
    /// See [`BigNumber::to_array_pad_zero`].
    pub fn to_array_pad_zero<const N: usize>(&self) -> Vec<u8> {
        self.0.to_array_pad_zero::<N>()
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

/// The unvalidated, wire-facing counterpart to [`PublicKey`].
///
/// This is the type that appears in structs sent over the network
/// (e.g. [`crate::HandshakeProof::A`]) and is the only public key type that
/// derives [`Deserialize`]. A derived `Deserialize` directly on [`PublicKey`]
/// would construct its inner value without going through [`PublicKey::new`],
/// letting a hostile payload reintroduce a degenerate key (e.g. `A = 0`) over
/// the wire. `#[serde(try_from = "..")]` can't fix this either, since
/// validation needs [`PrimeModulus`] `N`, which isn't part of the payload.
///
/// Call [`RawPublicKey::into_validated`] to turn this into a [`PublicKey`]
/// once `N` is available.
#[doc(alias("A", "B"))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawPublicKey(BigNumber);

impl RawPublicKey {
    /// Validates this raw value against `n`, see [`PublicKey::new`].
    pub fn into_validated(self, n: &PrimeModulus) -> Result<PublicKey> {
        PublicKey::new(self.0, n)
    }

    /// `raw` is expected to be big endian, see [`BigNumber::from_hex_str_be`].
    pub fn from_hex_str_be(str: &str) -> std::result::Result<Self, BigNumberError> {
        BigNumber::from_hex_str_be(str).map(Self)
    }

    /// The wire carries `A` and `B` little-endian, so this is the constructor
    /// for bytes received from a peer. See [`BigNumber::from_bytes_le`].
    pub fn from_bytes_le(raw: &[u8]) -> Self {
        Self(BigNumber::from_bytes_le(raw))
    }

    /// Big-endian bytes, zero-padded to at least `N` bytes.
    /// See [`BigNumber::to_array_pad_zero`].
    pub fn to_array_pad_zero<const N: usize>(&self) -> Vec<u8> {
        self.0.to_array_pad_zero::<N>()
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

    /// Access to the inner [`BigNumber`] for arithmetic. Validation stays the
    /// caller's explicit choice, which is why this is not a
    /// [`std::ops::Deref`] impl.
    pub fn as_bignum(&self) -> &BigNumber {
        &self.0
    }
}

impl Display for RawPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl From<PublicKey> for RawPublicKey {
    /// A validated [`PublicKey`] is always representable as a [`RawPublicKey`].
    fn from(key: PublicKey) -> Self {
        Self(key.0)
    }
}

#[test]
fn a_raw_key_round_trips_through_wire_bytes() {
    let bytes_le = [0x01, 0x02, 0x03];

    let key = RawPublicKey::from_bytes_le(&bytes_le);

    assert_eq!(key.as_bignum(), &BigNumber::from_bytes_le(&bytes_le));
    assert_eq!(key.to_vec(), vec![0x03, 0x02, 0x01]);
    assert_eq!(key.to_array_pad_zero::<5>(), vec![0, 0, 0x03, 0x02, 0x01]);
}

/// Refers to a private secret random number a (user), b (server)
#[doc(alias("a", "b", "x"))]
pub type PrivateKey = BigNumber;

/// A pair of [`PublicKey`] B and [`PrivateKey`] b
pub type KeyPair = (PublicKey, PrivateKey);

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

/// Username `I`, validated so it can never contain the `:` separator
/// used by [`calculate_p_hash`], a NUL byte, or be empty.
///
/// The colon rule matters because the private key derivation formula
/// `x = H(s | H(I ":" p))` joins the username and password with a
/// literal colon. If `I` itself could contain a colon, the pre-image
/// would become ambiguous: `("a:b", "c")` and `("a", "b:c")` would hash
/// to exactly the same value.
#[doc(alias = "I")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Username(String);
/// Reference to a validated [`Username`] `I`
pub type UsernameRef<'a> = &'a Username;

/// Errors returned by [`Username::new`]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum UsernameError {
    /// the username was empty
    #[error("username must not be empty")]
    Empty,

    /// the username contained a NUL byte
    #[error("username must not contain a NUL byte")]
    ContainsNulByte,

    /// the username contained a `:` (colon)
    ///
    /// `x = H(s | H(I ":" p))` joins the username and password with a
    /// literal colon, so a colon inside the username would make the
    /// pre-image ambiguous, e.g. `("a:b", "c")` and `("a", "b:c")` would
    /// hash identically.
    #[error(
        "username must not contain a ':' (colon): it is the separator in `H(I \":\" p)`, so \
         a colon inside the username would make the pre-image ambiguous, e.g. (\"a:b\", \"c\") \
         and (\"a\", \"b:c\") would hash identically"
    )]
    ContainsColon,

    /// the username did not satisfy the WoW 1.12.1 client's normalisation
    /// (see [`Username::new`] under the `wow-1-12-1` feature)
    #[cfg(feature = "wow-1-12-1")]
    #[error(
        "username must be 1 to 16 ASCII bytes without control characters (WoW client limitation)"
    )]
    InvalidWowUsername,
}

impl Username {
    /// The rules that hold for every flavour: non-empty, no NUL byte, no `:`.
    /// See the type documentation for why the colon is rejected.
    fn validate_common(s: &str) -> std::result::Result<(), UsernameError> {
        if s.is_empty() {
            return Err(UsernameError::Empty);
        }
        if s.contains('\0') {
            return Err(UsernameError::ContainsNulByte);
        }
        if s.contains(':') {
            return Err(UsernameError::ContainsColon);
        }

        Ok(())
    }

    /// Creates a new, validated [`Username`]
    ///
    /// # Errors
    /// Returns [`UsernameError`] if `s` is empty, contains a NUL byte, or
    /// contains a `:` (colon). See the type documentation for why the
    /// colon is rejected.
    #[cfg(not(feature = "wow-1-12-1"))]
    pub fn new(s: impl Into<String>) -> std::result::Result<Self, UsernameError> {
        let s = s.into();
        Self::validate_common(&s)?;

        Ok(Self(s))
    }

    /// Creates a new [`Username`] normalised the way the WoW 1.12.1 client
    /// does it: ASCII only, no control characters, 1 to 16 bytes, uppercased.
    ///
    /// This shadows the general constructor rather than sitting beside it as a
    /// second one, because a build talks to exactly one flavour of peer. With
    /// two constructors every call site would need its own `#[cfg]` to pick,
    /// and the paths that cannot take one - `TryFrom<String>`, and through it
    /// `Deserialize` - would silently keep the unnormalised form, so the same
    /// build could produce two different `Username`s for one input.
    ///
    /// # Errors
    /// Returns [`UsernameError`] if `s` is not 1 to 16 ASCII bytes without
    /// control characters, or fails the common validation (e.g. contains a
    /// colon).
    #[cfg(feature = "wow-1-12-1")]
    pub fn new(s: impl Into<String>) -> std::result::Result<Self, UsernameError> {
        let s = s.into();
        // The shared rules run first so that an empty, NUL-bearing or
        // colon-bearing name reports the rule it actually broke, the same way it
        // does without this feature. Checking the WoW envelope first would
        // report `InvalidWowUsername` for all three, since a NUL is also an
        // ASCII control character.
        Self::validate_common(&s)?;

        if s.len() > 16 || !s.is_ascii() || s.chars().any(|c| c.is_ascii_control()) {
            return Err(UsernameError::InvalidWowUsername);
        }

        // Re-validating after uppercasing would be redundant: `s` is ASCII, so
        // `to_uppercase` only maps a-z to A-Z and cannot introduce a NUL, a
        // colon, or emptiness.
        Ok(Self(s.to_uppercase()))
    }

    /// borrows the username as [`&str`]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Username {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<String> for Username {
    type Error = UsernameError;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::new(s)
    }
}

/// Clear text password `p` as [`str`]
#[doc(alias("P", "p"))]
pub type ClearTextPassword = String;
pub type ClearTextPasswordRef<'a> = &'a str;

// u = Hash(A, B)
// #[doc(alias = "u")]
// pub type Hash = BigLNumber;

/// [`Username`] and [`ClearTextPassword`] used on the client side
#[derive(Debug, Clone)]
pub struct UserCredentials<'a> {
    pub username: UsernameRef<'a>,
    pub password: ClearTextPasswordRef<'a>,
}

/// User details composes [`Username`], [`Salt`] and [`PasswordVerifier`] in one struct
#[derive(Debug, Clone)]
pub struct UserSecrets {
    pub username: Username,
    pub salt: Salt,
    pub verifier: PasswordVerifier,
}

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
    if (A.as_bignum() % N).is_zero() {
        return Err(Srp6Error::InvalidPublicKey(A.clone().into()));
    }

    let u = &calculate_u::<N_BYTE_LEN>(A, B);
    let base = &(A.as_bignum() * &v.modpow(u, N));
    let S: BigNumber = base.modpow(b, N);

    Ok(S)
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
    if (B.as_bignum() % N).is_zero() {
        return Err(Srp6Error::InvalidPublicKey(B.clone().into()));
    }

    let u = &calculate_u::<N_BYTE_LEN>(A, B);
    let exp: BigNumber = a + &(u * x);
    let g_mod_x = &g.modpow(x, N);
    let base = B.as_bignum() - &(k * g_mod_x);
    let S = base.modpow(&exp, N);

    Ok(S)
}

/// the hash of a session key `S` that is called `K`
/// S: is the session key of a user
/// K: is the hash of S, just not that straight
#[allow(non_snake_case)]
pub fn calculate_session_key_hash_interleave_K<const N_BYTE_LEN: usize>(
    S: &SessionKey,
) -> StrongSessionKey {
    let S = S.to_array_pad_zero::<N_BYTE_LEN>();

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
    let xor_hash: Hash = calculate_hash_N_xor_g::<N_BYTE_LEN>(N, g);
    let username_hash = HashFunc::new().chain(I.as_bytes()).finalize();

    let M = Proof::from_bytes_be(
        HashFunc::new()
            .chain(xor_hash)
            .chain(username_hash)
            .chain(s.to_array_pad_zero::<SALT_LENGTH>())
            .chain(A.to_array_pad_zero::<N_BYTE_LEN>())
            .chain(B.to_array_pad_zero::<N_BYTE_LEN>())
            .chain(K.to_array_pad_zero::<STRONG_SESSION_KEY_LENGTH>())
            .finalize()
            .as_slice(),
    );

    M
}

/// todo(verify): check if padding is needed or not
/// formula: `H(A | M | K)`
#[allow(non_snake_case)]
pub fn calculate_strong_proof_M2<const KEY_LENGTH: usize>(
    A: &PublicKey,
    M: &Proof,
    K: &StrongSessionKey,
) -> StrongProof {
    let M2: StrongProof = HashFunc::new()
        .chain(A.to_array_pad_zero::<KEY_LENGTH>())
        .chain(M.to_array_pad_zero::<HASH_LENGTH>())
        .chain(K.to_array_pad_zero::<STRONG_SESSION_KEY_LENGTH>())
        .into();

    M2
}

/// here we hash g and xor it with the hash of N
///
/// ```plain
/// M = H(H(N) xor H(g), H(I), s, A, B, K)
///       `````````````
///                    // this portion is calculated here
/// ```
#[allow(non_snake_case)]
fn calculate_hash_N_xor_g<const KEY_LENGTH: usize>(N: &PrimeModulus, g: &Generator) -> Hash {
    let mut h = HashFunc::new()
        .chain(N.to_array_pad_zero::<KEY_LENGTH>())
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
    g.modpow(x, N)
}

/// `u` is the hash of host's [`PublicKey`][`crate::rfc_lingo::A`] and client's [`PublicKey`][`crate::rfc_lingo::B`]
/// formula: `H(PAD(A) | PAD(B))`
/// The Padding is based on the key length, e.g. if N is 1024 bit, the padding is 128 bytes
#[allow(non_snake_case)]
pub fn calculate_u<const N_BYTE_LEN: usize>(A: &PublicKey, B: &PublicKey) -> BigNumber {
    hash_w_pad::<N_BYTE_LEN>(A.as_bignum(), B.as_bignum())
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
    PublicKey::new(g.modpow(a, N), N)
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
    let g_mod_N = g.modpow(b, N);
    // This is B
    PublicKey::new(&((k * v) + g_mod_N) % N, N)
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

/// [`Salt`] `s` is a random number
pub fn generate_salt<const SALT_LENGTH: usize>() -> Salt {
    Salt::new_rand(SALT_LENGTH)
}

#[cfg(test)]
mod username_tests {
    use super::*;

    /// The WoW flavour uppercases, so it asserts its own form in
    /// `should_uppercase_for_wow` below.
    #[cfg(not(feature = "wow-1-12-1"))]
    #[test]
    fn should_accept_a_normal_username() {
        assert_eq!(Username::new("alice").unwrap().as_str(), "alice");
    }

    #[test]
    fn should_reject_an_empty_username() {
        assert_eq!(Username::new("").unwrap_err(), UsernameError::Empty);
    }

    #[test]
    fn should_reject_a_nul_byte() {
        assert_eq!(
            Username::new("ali\0ce").unwrap_err(),
            UsernameError::ContainsNulByte
        );
    }

    #[test]
    fn should_reject_a_colon() {
        assert_eq!(
            Username::new("ali:ce").unwrap_err(),
            UsernameError::ContainsColon
        );
    }

    /// Flavour-agnostic: the wire form is the username's own normalised form,
    /// whichever flavour is compiled in.
    #[test]
    fn should_round_trip_through_serde_json() {
        let username = Username::new("alice").unwrap();
        let json = serde_json::to_string(&username).unwrap();
        assert_eq!(json, format!("\"{}\"", username.as_str()));
        assert_eq!(serde_json::from_str::<Username>(&json).unwrap(), username);
    }

    #[test]
    fn should_reject_an_invalid_username_on_deserialize() {
        let err = serde_json::from_str::<Username>("\"ali:ce\"").unwrap_err();
        assert!(err.to_string().contains("colon"));
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_uppercase_for_wow() {
        assert_eq!(Username::new("alice").unwrap().as_str(), "ALICE");
    }

    /// Why `new` is shadowed instead of paired with a separate `new_wow`:
    /// `Deserialize` reaches the constructor through `TryFrom<String>`, so it
    /// has to pick up the flavour's normalisation too. With a second
    /// constructor this path kept the unnormalised form and yielded "alice",
    /// disagreeing with a directly constructed `Username` in the same build.
    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_uppercase_on_deserialize_for_wow() {
        let deserialized: Username = serde_json::from_str("\"alice\"").unwrap();
        assert_eq!(deserialized.as_str(), "ALICE");
        assert_eq!(deserialized, Username::new("alice").unwrap());
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_reject_a_too_long_username_for_wow() {
        assert_eq!(
            Username::new("a_name_longer_than_16_bytes").unwrap_err(),
            UsernameError::InvalidWowUsername
        );
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_reject_non_ascii_for_wow() {
        assert_eq!(
            Username::new("älice").unwrap_err(),
            UsernameError::InvalidWowUsername
        );
    }
}
