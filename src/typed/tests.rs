use super::*;
use crate::big_number::BigNumber;
use crate::credentials::Username;
use crate::group::{Group2048, Group4096, GroupOps};
use crate::hash::HASH_LENGTH;

#[cfg(feature = "wow-1-12-1")]
use crate::group::GroupWow;

fn round_trip<G: GroupOps>(group: G) {
    let srp = Srp6::new(group);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
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
    let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
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
    srp.start_handshake(&username, salt, verifier);
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
    srp.start_handshake(&username, salt, verifier);
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
fn the_strong_session_key_round_trips_through_hex() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
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
fn the_numeric_hex_path_round_trips_its_display() {
    let value = BigNumber::try_from_hex("BEB25379D1A8581EB5A727673A2441EE").unwrap();

    assert_eq!(BigNumber::try_from_hex(&value.to_string()).unwrap(), value);
}

#[test]
fn the_strong_session_key_is_two_hashes_wide() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
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
