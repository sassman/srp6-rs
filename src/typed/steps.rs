//! Hash-only protocol steps shared by the handshake and the golden vectors.
//!
//! These steps never touch the group arithmetic. Keeping them byte-based is
//! what removes the numeric round-trip from the production path.

use crate::credentials::{ClearTextPasswordRef, UsernameRef};
use crate::group::GroupOps;
use crate::hash::{Digest, Output};

use super::{FieldElement, Proof, PublicKey, Salt, StrongSessionKey};

pub(crate) fn p_hash<H: Digest>(
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
) -> Output<H> {
    // The WoW client uppercases the password at the point of use; the
    // username is already normalised by `Username::new`.
    #[cfg(feature = "wow-1-12-1")]
    let password: String = password.to_uppercase();

    H::new()
        .chain_update(username.as_bytes())
        .chain_update(b":")
        .chain_update(password.as_bytes())
        .finalize()
}

pub(crate) fn x_hash<H: Digest>(
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
    salt: &Salt,
) -> Output<H> {
    // The salt is hashed as stored; a numeric round-trip would trim leading
    // zero bytes before they reach the hash.
    H::new()
        .chain_update(salt.as_bytes())
        .chain_update(p_hash::<H>(username, password))
        .finalize()
}

/// The multiplier `k`. A group may fix it as a constant; otherwise it is
/// `k = H(N | PAD(g))` (RFC 5054), hashed in the group's byte order - which is why
/// it lives here, where `H` is known, rather than on the hash-agnostic group.
pub(crate) fn multiplier<G: GroupOps, H: Digest>(group: &G) -> G::Field {
    if let Some(bytes) = group.multiplier_constant() {
        return group
            .field_from_bytes(&bytes)
            .expect("a sealed group's constant multiplier is a valid field element");
    }

    let modulus = group.modulus();
    let g_padded = group.field_to_bytes(&group.generator());
    let digest = H::new()
        .chain_update(modulus.as_bytes())
        .chain_update(&g_padded)
        .finalize();
    group
        .field_from_bytes(digest.as_slice())
        .expect("a sealed group's hashed multiplier is a valid field element")
}

pub(crate) fn private_key_x<G: GroupOps, H: Digest>(
    group: &G,
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
    salt: &Salt,
) -> G::Exponent {
    group.exponent_from_hash(x_hash::<H>(username, password, salt).as_slice())
}

pub(crate) fn scrambler_u<G: GroupOps, H: Digest>(
    group: &G,
    a: &PublicKey<G>,
    b: &PublicKey<G>,
) -> G::Exponent {
    let hash = H::new()
        .chain_update(a.as_bytes())
        .chain_update(b.as_bytes())
        .finalize();
    group.exponent_from_hash(hash.as_slice())
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

pub(crate) fn strong_session_key<G: GroupOps, H: Digest>(
    s: &FieldElement<G>,
) -> StrongSessionKey<H> {
    strong_session_key_bytes::<H>(s.as_bytes())
}

pub(crate) fn strong_session_key_bytes<H: Digest>(s: &[u8]) -> StrongSessionKey<H> {
    debug_assert!(s.len().is_multiple_of(2));
    let half = s.len() / 2;
    let mut even = Vec::with_capacity(half);
    let mut odd = Vec::with_capacity(half);
    for pair in s.chunks_exact(2) {
        even.push(pair[0]);
        odd.push(pair[1]);
    }

    let even_hash = H::new().chain_update(&even).finalize();
    let odd_hash = H::new().chain_update(&odd).finalize();

    let mut key = vec![0_u8; even_hash.len() + odd_hash.len()];
    for (i, (even, odd)) in even_hash.iter().zip(odd_hash.iter()).enumerate() {
        key[i * 2] = *even;
        key[i * 2 + 1] = *odd;
    }

    StrongSessionKey::from_key(key)
}

pub(crate) fn proof_m1<G: GroupOps, H: Digest>(
    group: &G,
    username: UsernameRef<'_>,
    salt: &Salt,
    a: &PublicKey<G>,
    b: &PublicKey<G>,
    k: &StrongSessionKey<H>,
) -> Proof<H> {
    // The salt is hashed as stored, like in `x`: RFC 2945's PAD() covers only
    // the group elements, and a padded salt breaks interop with conformant
    // peers for any salt shorter than the pad.
    let digest = H::new()
        .chain_update(hash_n_xor_g::<G, H>(group))
        .chain_update(H::new().chain_update(username.as_bytes()).finalize())
        .chain_update(salt.as_bytes())
        .chain_update(a.as_bytes())
        .chain_update(b.as_bytes())
        .chain_update(k.as_bytes())
        .finalize();

    Proof::from_hash(digest)
}

pub(crate) fn proof_m2<G: GroupOps, H: Digest>(
    a: &PublicKey<G>,
    m1: &Proof<H>,
    k: &StrongSessionKey<H>,
) -> Proof<H> {
    let digest = H::new()
        .chain_update(a.as_bytes())
        .chain_update(m1.as_bytes())
        .chain_update(k.as_bytes())
        .finalize();

    Proof::from_hash(digest)
}

fn hash_n_xor_g<G: GroupOps, H: Digest>(group: &G) -> Output<H> {
    let modulus = group.modulus();
    let mut n_hash = H::new().chain_update(modulus.as_bytes()).finalize();

    // RFC 5054 hashes N at full width and g in its minimal form.
    let generator = group.generator();
    let generator_bytes = group.field_to_bytes(&generator);
    let g_hash = H::new()
        .chain_update(trim_leading_zeroes(&generator_bytes))
        .finalize();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Username;
    use crate::group::Group;
    use crate::hash::DefaultHash;

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
        let group = crate::group::Group2048;
        let full = group.field_to_bytes(&group.generator());
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

        let u = scrambler_u::<_, DefaultHash>(&crate::group::Group2048, &a, &b);
        let expected = crate::group::Group2048.exponent_from_hash(
            DefaultHash::new()
                .chain_update(&a_bytes)
                .chain_update(&b_bytes)
                .finalize()
                .as_slice(),
        );

        assert_eq!(u, expected);
    }

    #[test]
    fn the_salt_is_hashed_with_its_leading_zeroes() {
        let username = Username::new("alice").expect("valid username");
        let salt = Salt::from(vec![0x00, 0xBE, 0xB2]);
        let with_zero = x_hash::<DefaultHash>(&username, "password123", &salt);

        let trimmed = Salt::from(vec![0xBE, 0xB2]);
        let without_zero = x_hash::<DefaultHash>(&username, "password123", &trimmed);

        assert_ne!(with_zero, without_zero);
    }

    #[test]
    fn trimming_an_all_zero_generator_leaves_one_zero() {
        assert_eq!(trim_leading_zeroes(&[0, 0, 0]), [0_u8].as_slice());
    }

    /// Under the old left-pad both salts hashed identically; a conformant M1
    /// must tell them apart, exactly as `x` does.
    #[test]
    fn the_m1_salt_is_hashed_as_stored() {
        let group = crate::group::Group2048;
        let username = Username::new("alice").expect("valid username");
        let mut a_bytes = vec![0_u8; crate::group::Group2048::N_BYTES];
        a_bytes[crate::group::Group2048::N_BYTES - 1] = 2;
        let mut b_bytes = vec![0_u8; crate::group::Group2048::N_BYTES];
        b_bytes[crate::group::Group2048::N_BYTES - 1] = 3;
        let a = PublicKey::<crate::group::Group2048>::try_from_bytes(&a_bytes).expect("valid A");
        let b = PublicKey::<crate::group::Group2048>::try_from_bytes(&b_bytes).expect("valid B");
        let k = strong_session_key_bytes::<DefaultHash>(&[0xAB; 32]);

        let with_zero = proof_m1(
            &group,
            &username,
            &Salt::from([0x00, 0xBE, 0xB2].as_slice()),
            &a,
            &b,
            &k,
        );
        let trimmed = proof_m1(
            &group,
            &username,
            &Salt::from([0xBE, 0xB2].as_slice()),
            &a,
            &b,
            &k,
        );

        assert_ne!(with_zero, trimmed);
    }
}
