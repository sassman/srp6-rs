use super::PublicKey;
use crate::big_number::BigNumber;
use crate::hash::*;

/// `u` is the hash of the host's public key `A` and the client's public key `B`
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
