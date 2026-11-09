//! The boundary a caller sees: the typed handshake and byte-backed values.

use srp6::hash::HASH_LENGTH;
use srp6::{FromHexString, Group2048, Proof, Salt, Srp6, StrongSessionKey, Username, Verifier};

#[test]
fn the_typed_handshake_is_reachable_from_outside_the_crate() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    assert_eq!(salt.as_bytes().len(), 256);
    assert_eq!(verifier.as_bytes().len(), 256);

    let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
    assert_eq!(handshake.s.as_bytes().len(), 256);

    let (proof, strong_verifier) = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");

    assert_eq!(k, strong_verifier.K);
}

#[test]
fn the_public_types_parse_their_printed_hex() {
    let salt = Salt::try_from_hex("00AB").expect("valid hex");
    assert_eq!(salt.as_bytes(), &[0x00, 0xAB]);

    let verifier_hex = format!("01{}", "00".repeat(255));
    let verifier = Verifier::<Group2048>::try_from_hex(&verifier_hex).expect("valid field element");
    assert_eq!(verifier.as_bytes().len(), 256);

    let proof = Proof::try_from_hex(&"00".repeat(HASH_LENGTH)).expect("valid proof");
    assert_eq!(proof.as_bytes().len(), HASH_LENGTH);

    let key = StrongSessionKey::try_from_hex(&"00".repeat(2 * HASH_LENGTH)).expect("valid key");
    assert_eq!(key.as_bytes().len(), 2 * HASH_LENGTH);
}
