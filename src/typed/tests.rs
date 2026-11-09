use super::*;
use crate::credentials::Username;
use crate::group::{Group, Group2048, Group4096, GroupOps};
use crate::hash::HASH_LENGTH;

#[cfg(feature = "wow-1-12-1")]
use crate::group::GroupWow;

fn round_trip<G: GroupOps>(group: G) {
    let srp = Srp6::new(group);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let (proof, strong_verifier) = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    srp.verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");
}

#[test]
fn a_2048_bit_handshake_round_trips() {
    round_trip(Group2048);
}

#[test]
fn a_4096_bit_handshake_round_trips() {
    round_trip(Group4096);
}

#[cfg(feature = "wow-1-12-1")]
#[test]
fn a_wow_handshake_round_trips() {
    round_trip(GroupWow);
}

#[test]
fn a_wrong_password_is_refused() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let (proof, _) = srp
        .calculate_proof(&handshake, &username, "wrong")
        .expect("the client can prove");
    assert!(srp.verify_proof(&proof_verifier, &proof).is_err());
}

#[test]
fn a_verifier_round_trips_through_its_bytes() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");

    let salt = Salt::from(salt.to_vec());
    let verifier = Verifier::<Group2048>::from_bytes(&verifier.to_bytes())
        .expect("the verifier is a field element");
    srp.start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
}

#[test]
fn a_public_key_is_a_distinct_validated_type() {
    let mut bytes = vec![0_u8; Group2048::N_BYTES];
    bytes[Group2048::N_BYTES - 1] = 2;

    let key = PublicKey::<Group2048>::from_bytes(&bytes).expect("a non-zero key");
    assert_eq!(key.as_bytes(), bytes.as_slice());
    assert!(format!("{key:?}").starts_with("PublicKey("));

    assert!(PublicKey::<Group2048>::from_bytes(&[0_u8; 256]).is_err());
    assert!(PublicKey::<Group2048>::from_bytes(&vec![0_u8; 257]).is_err());
}

#[test]
fn degenerate_values_are_refused() {
    assert!(Verifier::<Group2048>::from_bytes(&[0_u8; 256]).is_err());
    assert!(Verifier::<Group2048>::from_bytes(&[0_u8; 257]).is_err());
    assert!(Proof::from_bytes(&[0_u8; HASH_LENGTH - 1]).is_err());
}

#[test]
fn hex_round_trips_through_the_boundary_types() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");

    let salt = Salt::try_from_hex(&salt.to_string()).expect("the salt hex decodes");
    let verifier = Verifier::<Group2048>::try_from_hex(&verifier.to_string())
        .expect("the verifier hex decodes");
    srp.start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
}

#[test]
fn hex_decoding_preserves_leading_zero_bytes() {
    let salt = Salt::try_from_hex("00ab").expect("valid hex");
    assert_eq!(salt.as_bytes(), &[0x00, 0xAB]);
    assert_eq!(salt.to_string(), "00AB");
}

#[test]
fn hex_decoding_strips_whitespace_between_octlets() {
    let contiguous = Salt::try_from_hex("00ABCDEF").expect("valid hex");

    assert_eq!(
        contiguous,
        Salt::try_from_hex("00 AB CD EF").expect("spaces between octlets")
    );
    assert_eq!(
        contiguous,
        Salt::try_from_hex("\r\n00\tAB\r\nCD EF\n").expect("CRLF and tabs")
    );
}

#[test]
fn invalid_hex_is_refused() {
    assert!(Salt::try_from_hex("ABC").is_err());
    assert!(Salt::try_from_hex("zz").is_err());
    assert!(Salt::try_from_hex("é0").is_err());
    assert!(Proof::try_from_hex("00").is_err());
    assert!(Verifier::<Group2048>::try_from_hex("00").is_err());
}

#[test]
fn the_boundary_types_round_trip_through_json() {
    let salt = Salt::try_from_hex("00AB").expect("valid hex");
    let json = serde_json::to_string(&salt).expect("the salt serializes");
    let back: Salt = serde_json::from_str(&json).expect("the salt deserializes");
    assert_eq!(salt, back);

    let proof = Proof::try_from_hex(&"00".repeat(HASH_LENGTH)).expect("valid proof");
    let json = serde_json::to_string(&proof).expect("the proof serializes");
    let back: Proof = serde_json::from_str(&json).expect("the proof deserializes");
    assert_eq!(proof, back);
}

#[test]
fn the_strong_session_key_round_trips_through_hex() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let (proof, strong_verifier) = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");

    assert_eq!(StrongSessionKey::try_from_hex(&k.to_string()).unwrap(), k);
    assert!(StrongSessionKey::try_from_hex("00").is_err());
}

#[test]
fn the_strong_session_key_is_two_hashes_wide() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let (proof, strong_verifier) = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");

    assert_eq!(k.as_bytes().len(), 2 * HASH_LENGTH);
    assert_eq!(k, strong_verifier.K);
}
