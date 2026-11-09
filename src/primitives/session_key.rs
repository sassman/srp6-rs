use crypto_bigint::ConcatenatingMul;

use super::montgomery::{field, field_bytes, is_zero_mod, monty_params};
use super::scrambler::calculate_u;
use super::{
    Generator, MultiplierParameter, PasswordVerifier, PrimeModulus, PrivateKey, PublicKey,
    SessionKey, StrongSessionKey,
};
use crate::hash::*;
use crate::{error::Srp6Error, Result};

/// host version of a session key for a given user
/// S: is the session key of a user
/// u: is the hash of user and server pub keys
///
/// u = H(A, B)
/// S = (Av^u) ^ b
#[allow(non_snake_case)]
pub(crate) fn calculate_session_key_S_for_host<const N_BYTE_LEN: usize>(
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
pub(crate) fn calculate_session_key_S_for_client<const N_BYTE_LEN: usize>(
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
pub(crate) fn calculate_session_key_hash_interleave_K<const N_BYTE_LEN: usize>(
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
