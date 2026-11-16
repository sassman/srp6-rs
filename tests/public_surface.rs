//! The boundary a caller sees: the typed handshake and byte-backed values.

use srp6::{
    DefaultHash, Digest, FromHexString, Group, Group2048, Proof, PublicKey, Salt, SaltBytes,
    Srp6_2048, StrongSessionKey, Username, Verifier,
};

#[test]
fn the_typed_handshake_is_reachable_from_outside_the_crate() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    assert_eq!(verifier.as_bytes().len(), 256);

    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");

    let (proof, strong_verifier) = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let (m2, server_key) = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");

    assert_eq!(k, *strong_verifier.session_key());
    assert_eq!(k, server_key);
}

#[test]
fn the_salt_width_is_overridable_from_outside_the_crate() {
    let username = Username::new("alice").expect("valid username");
    let custom = SaltBytes::custom(24).expect("within bounds");
    let srp = Srp6_2048::default().with_salt(custom);

    let (salt, _) = srp.generate_new_user_secrets(&username, "password123");

    assert_eq!(salt.as_bytes().len(), 24);
    assert!(SaltBytes::custom(7).is_err());
    assert!(SaltBytes::custom(256).is_err());
}

#[test]
fn a_public_key_is_constructible_and_checked_at_the_boundary() {
    let mut bytes = vec![0_u8; Group2048::N_BYTES];
    bytes[Group2048::N_BYTES - 1] = 2;

    let key = PublicKey::<Group2048>::try_from_bytes(&bytes).expect("a non-zero key");
    assert_eq!(key.as_bytes(), bytes.as_slice());

    assert!(PublicKey::<Group2048>::try_from_bytes(&[0_u8; 256]).is_err());
}

#[test]
fn the_public_types_parse_their_printed_hex() {
    let salt = Salt::try_from_hex("00AB").expect("valid hex");
    assert_eq!(salt.as_bytes(), &[0x00, 0xAB]);

    let verifier_hex = format!("01{}", "00".repeat(255));
    let verifier = Verifier::<Group2048>::try_from_hex(&verifier_hex).expect("valid field element");
    assert_eq!(verifier.as_bytes().len(), 256);

    let hash_len = <DefaultHash as Digest>::output_size();
    let proof = Proof::<DefaultHash>::try_from_hex(&"00".repeat(hash_len)).expect("valid proof");
    assert_eq!(proof.as_bytes().len(), hash_len);

    let key = StrongSessionKey::<DefaultHash>::try_from_hex(&"00".repeat(2 * hash_len))
        .expect("valid key");
    assert_eq!(key.as_bytes().len(), 2 * hash_len);
}

/// A client checks the group a server names against its own, so both `N` and `g` are
/// reachable from the driver without touching the group's arithmetic.
#[test]
fn the_driver_names_its_groups_generator() {
    let srp = Srp6_2048::default();
    let g = srp.generator();
    assert_eq!(g.as_bytes().len(), Group2048::N_BYTES);
    assert_eq!(g.as_bytes().last(), Some(&2));
    assert!(g.as_bytes()[..Group2048::N_BYTES - 1]
        .iter()
        .all(|byte| *byte == 0));
}
