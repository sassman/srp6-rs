//! Hash-only protocol steps shared by the handshake and the golden vectors.
//!
//! These steps never touch the group arithmetic. Keeping them byte-based is
//! what removes the numeric round-trip from the production path.

use crate::credentials::{ClearTextPasswordRef, UsernameRef};
use crate::group::GroupOps;
use crate::hash::{Digest, Hash, HashFunc, Update, STRONG_SESSION_KEY_LENGTH};

use super::{FieldElement, Proof, PublicKey, Salt, StrongSessionKey};

pub(crate) fn p_hash(username: UsernameRef<'_>, password: ClearTextPasswordRef<'_>) -> Hash {
    // The WoW client uppercases the password at the point of use; the
    // username is already normalised by `Username::new`.
    #[cfg(feature = "wow-1-12-1")]
    let password: String = password.to_uppercase();

    HashFunc::new()
        .chain(username.as_bytes())
        .chain(b":")
        .chain(password.as_bytes())
        .finalize()
        .into()
}

pub(crate) fn x_hash(
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
    salt: &Salt,
) -> Hash {
    // The salt is hashed as stored; a numeric round-trip would trim leading
    // zero bytes before they reach the hash.
    HashFunc::new()
        .chain(salt.as_bytes())
        .chain(p_hash(username, password))
        .finalize()
        .into()
}

pub(crate) fn private_key_x<G: GroupOps>(
    group: &G,
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
    salt: &Salt,
) -> G::Exponent {
    group.exponent_from_hash(&x_hash(username, password, salt))
}

pub(crate) fn scrambler_u<G: GroupOps>(
    group: &G,
    a: &PublicKey<G>,
    b: &PublicKey<G>,
) -> G::Exponent {
    let hash: Hash = HashFunc::new()
        .chain(a.as_bytes())
        .chain(b.as_bytes())
        .finalize()
        .into();
    group.exponent_from_hash(&hash)
}

/// Rejects the degenerate scrambler `u == 0`. `protocol_details` states both
/// sides MUST abort on it; `u` is public (`H(A | B)`), so a plain byte check is
/// fine here.
pub(crate) fn is_zero_exponent<G: GroupOps>(group: &G, exponent: &G::Exponent) -> bool {
    group
        .exponent_to_bytes(exponent)
        .iter()
        .all(|byte| *byte == 0)
}

pub(crate) fn strong_session_key<G: GroupOps>(s: &FieldElement<G>) -> StrongSessionKey {
    strong_session_key_bytes(s.as_bytes())
}

pub(crate) fn strong_session_key_bytes(s: &[u8]) -> StrongSessionKey {
    debug_assert!(s.len().is_multiple_of(2));
    let half = s.len() / 2;
    let mut even = Vec::with_capacity(half);
    let mut odd = Vec::with_capacity(half);
    for pair in s.chunks_exact(2) {
        even.push(pair[0]);
        odd.push(pair[1]);
    }

    let even_hash: Hash = HashFunc::new().chain(&even).finalize().into();
    let odd_hash: Hash = HashFunc::new().chain(&odd).finalize().into();

    let mut key = [0_u8; STRONG_SESSION_KEY_LENGTH];
    for (i, (even, odd)) in even_hash.iter().zip(odd_hash.iter()).enumerate() {
        key[i * 2] = *even;
        key[i * 2 + 1] = *odd;
    }

    StrongSessionKey::from_key(key)
}

pub(crate) fn proof_m1<G: GroupOps>(
    group: &G,
    username: UsernameRef<'_>,
    salt: &Salt,
    a: &PublicKey<G>,
    b: &PublicKey<G>,
    k: &StrongSessionKey,
) -> Proof {
    // Parked (ISSUE-PAD-LEFT): pads to the group's advisory default until the
    // raw-vs-padded salt hashing question resolves; a no-op for any salt at
    // least that wide, which generated salts are.
    let salt = pad_left(salt.as_bytes(), G::DEFAULT_SALT_BYTES);
    let digest: Hash = HashFunc::new()
        .chain(hash_n_xor_g(group))
        .chain(HashFunc::new().chain(username.as_bytes()).finalize())
        .chain(salt)
        .chain(a.as_bytes())
        .chain(b.as_bytes())
        .chain(k.as_bytes())
        .finalize()
        .into();

    Proof::from_hash(digest)
}

pub(crate) fn proof_m2<G: GroupOps>(a: &PublicKey<G>, m1: &Proof, k: &StrongSessionKey) -> Proof {
    let digest: Hash = HashFunc::new()
        .chain(a.as_bytes())
        .chain(m1.as_bytes())
        .chain(k.as_bytes())
        .finalize()
        .into();

    Proof::from_hash(digest)
}

fn hash_n_xor_g<G: GroupOps>(group: &G) -> Hash {
    let modulus = group.modulus();
    let mut n_hash: Hash = HashFunc::new().chain(modulus.as_bytes()).finalize().into();

    // RFC 5054 hashes N at full width and g in its minimal form.
    let generator = group.generator();
    let generator_bytes = group.field_to_bytes(&generator);
    let g_hash: Hash = HashFunc::new()
        .chain(trim_leading_zeroes(&generator_bytes))
        .finalize()
        .into();

    for (n, g) in n_hash.iter_mut().zip(g_hash.iter()) {
        *n ^= *g;
    }
    n_hash
}

fn trim_leading_zeroes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte != 0) {
        Some(start) => &bytes[start..],
        // All-zero input collapses to a single zero byte: an empty slice would
        // hash differently from the minimal-form encoding the RFC expects.
        None => &bytes[bytes.len().saturating_sub(1)..],
    }
}

fn pad_left(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes.to_vec();
    }
    let mut padded = vec![0_u8; width];
    padded[width - bytes.len()..].copy_from_slice(bytes);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Username;
    use crate::group::Group;

    #[test]
    fn the_zero_scrambler_is_detected() {
        let group = crate::group::Group2048;
        assert!(is_zero_exponent(
            &group,
            &group.exponent_from_bytes(&[0_u8])
        ));
        assert!(!is_zero_exponent(
            &group,
            &group.exponent_from_bytes(&[1_u8])
        ));
    }

    #[test]
    fn the_generator_is_hashed_in_its_minimal_form() {
        let full = crate::group::Group2048.generator_bytes();
        let minimal = trim_leading_zeroes(&full);

        assert_eq!(minimal, [2_u8].as_slice());
    }

    #[test]
    fn the_scrambler_hashes_the_fixed_width_keys() {
        let mut a_bytes = vec![0_u8; crate::group::Group2048::N_BYTES];
        a_bytes[crate::group::Group2048::N_BYTES - 1] = 2;
        let mut b_bytes = vec![0_u8; crate::group::Group2048::N_BYTES];
        b_bytes[crate::group::Group2048::N_BYTES - 1] = 3;

        let a = PublicKey::<crate::group::Group2048>::try_from_bytes(&a_bytes).expect("valid A");
        let b = PublicKey::<crate::group::Group2048>::try_from_bytes(&b_bytes).expect("valid B");

        let u = scrambler_u(&crate::group::Group2048, &a, &b);
        let expected = crate::group::Group2048
            .exponent_from_hash(&HashFunc::new().chain(&a_bytes).chain(&b_bytes).finalize());

        assert_eq!(u, expected);
    }

    #[test]
    fn the_salt_is_hashed_with_its_leading_zeroes() {
        let username = Username::new("alice").expect("valid username");
        let salt = Salt::from(vec![0x00, 0xBE, 0xB2]);
        let with_zero = x_hash(&username, "password123", &salt);

        let trimmed = Salt::from(vec![0xBE, 0xB2]);
        let without_zero = x_hash(&username, "password123", &trimmed);

        assert_ne!(with_zero, without_zero);
    }

    #[test]
    fn trimming_an_all_zero_generator_leaves_one_zero() {
        assert_eq!(trim_leading_zeroes(&[0, 0, 0]), [0_u8].as_slice());
    }
}
