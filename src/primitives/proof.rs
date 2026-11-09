use super::{Generator, PrimeModulus, Proof, PublicKey, Salt, StrongProof, StrongSessionKey};
use crate::credentials::UsernameRef;
use crate::hash::*;

#[allow(non_snake_case)]
pub(crate) fn calculate_proof_M<const N_BYTE_LEN: usize, const SALT_LENGTH: usize>(
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
pub(crate) fn calculate_strong_proof_M2<const KEY_LENGTH: usize>(
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
///       ^^^^^^^^^^^^^
///              \ this portion we are talking about
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
