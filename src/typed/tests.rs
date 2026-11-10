use std::convert::TryFrom;

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
fn a_wrong_strong_proof_is_refused() {
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

    let mut wrong = *m2.as_bytes();
    wrong[0] ^= 1;
    let wrong = Proof::try_from_bytes(&wrong).expect("one proof width");

    assert!(srp.verify_strong_proof(&strong_verifier, &wrong).is_err());
}

#[test]
fn a_verifier_round_trips_through_its_bytes() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");

    let salt = Salt::from(salt.to_vec());
    let verifier = Verifier::<Group2048>::try_from_bytes(&verifier.to_vec())
        .expect("the verifier is a field element");
    srp.start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
}

#[test]
fn a_public_key_is_a_distinct_validated_type() {
    let mut bytes = vec![0_u8; Group2048::N_BYTES];
    bytes[Group2048::N_BYTES - 1] = 2;

    let key = PublicKey::<Group2048>::try_from_bytes(&bytes).expect("a non-zero key");
    assert_eq!(key.as_bytes(), bytes.as_slice());
    assert!(format!("{key:?}").starts_with("PublicKey("));

    assert!(PublicKey::<Group2048>::try_from_bytes(&[0_u8; 256]).is_err());
    assert!(PublicKey::<Group2048>::try_from_bytes(&vec![0_u8; 257]).is_err());
}

#[test]
fn degenerate_values_are_refused() {
    assert!(Verifier::<Group2048>::try_from_bytes(&[0_u8; 256]).is_err());
    assert!(Verifier::<Group2048>::try_from_bytes(&[0_u8; 257]).is_err());
    assert!(Proof::try_from_bytes(&[0_u8; HASH_LENGTH - 1]).is_err());
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

#[test]
fn the_handshake_accessors_expose_the_same_values() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let (proof, strong_verifier) = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");

    assert_eq!(handshake.public_key(), &handshake.B);
    assert_eq!(handshake.generator(), &handshake.g);
    assert_eq!(handshake.multiplier(), &handshake.k);
    assert_eq!(handshake.salt(), &handshake.s);

    assert_eq!(proof_verifier.public_key(), &proof_verifier.B);
    assert_eq!(proof_verifier.generator(), &proof_verifier.g);
    assert_eq!(
        proof_verifier.user().username(),
        &proof_verifier.user.username
    );
    assert_eq!(proof_verifier.user().salt(), &proof_verifier.user.salt);
    assert_eq!(
        proof_verifier.user().verifier(),
        &proof_verifier.user.verifier
    );

    assert_eq!(proof.public_key(), &proof.A);
    assert_eq!(proof.proof(), &proof.M1);

    assert_eq!(strong_verifier.public_key(), &strong_verifier.A);
    assert_eq!(strong_verifier.proof(), &strong_verifier.M1);
    assert_eq!(strong_verifier.session_key(), &strong_verifier.K);
}

#[test]
fn the_modulus_exposes_its_bytes_and_display() {
    let modulus = Group2048.modulus();
    let bytes = Group2048.modulus_bytes();

    assert_eq!(modulus.as_bytes(), bytes.as_slice());
    assert_eq!(modulus.to_vec(), bytes);
    assert_eq!(
        <Modulus<Group2048> as AsRef<[u8]>>::as_ref(&modulus),
        modulus.as_bytes()
    );
    assert_eq!(Vec::<u8>::from(modulus.clone()), modulus.to_vec());
    assert_eq!(modulus, Group2048.modulus());
    assert_eq!(modulus.to_string().len(), bytes.len() * 2);
    assert!(format!("{modulus:?}").starts_with("Modulus("));
}

#[test]
fn the_verifier_implements_its_byte_contract() {
    let srp = Srp6::new(Group2048);
    let username = Username::new("alice").expect("valid username");
    let (_, verifier) = srp.generate_new_user_secrets(&username, "password123");

    let cloned = verifier.clone();
    assert_eq!(cloned, verifier);
    assert_eq!(cloned.as_bytes(), verifier.as_bytes());
    assert_eq!(cloned.to_vec(), verifier.to_vec());
    assert_eq!(
        <Verifier<Group2048> as AsRef<[u8]>>::as_ref(&verifier),
        verifier.as_bytes()
    );
    assert_eq!(Vec::<u8>::from(verifier.clone()), verifier.to_vec());
    assert_eq!(
        Verifier::<Group2048>::try_from(verifier.to_vec()).expect("owned bytes"),
        verifier
    );
    assert_eq!(
        Verifier::<Group2048>::try_from(verifier.as_bytes()).expect("borrowed bytes"),
        verifier
    );
    assert_eq!(
        Verifier::<Group2048>::try_from_hex(&verifier.to_string()).expect("printed hex"),
        verifier
    );
    assert!(format!("{verifier:?}").starts_with("FieldElement("));

    let json = serde_json::to_string(&verifier).expect("the verifier serializes");
    let back: Verifier<Group2048> = serde_json::from_str(&json).expect("the verifier deserializes");
    assert_eq!(back, verifier);
}

#[test]
fn the_public_key_implements_its_byte_contract() {
    let mut bytes = vec![0_u8; Group2048::N_BYTES];
    bytes[Group2048::N_BYTES - 1] = 2;
    let key = PublicKey::<Group2048>::try_from_bytes(&bytes).expect("a non-zero key");

    let cloned = key.clone();
    assert_eq!(cloned, key);
    assert_eq!(cloned.as_bytes(), key.as_bytes());
    assert_eq!(cloned.to_vec(), key.to_vec());
    assert_eq!(
        <PublicKey<Group2048> as AsRef<[u8]>>::as_ref(&key),
        key.as_bytes()
    );
    assert_eq!(Vec::<u8>::from(key.clone()), key.to_vec());
    assert_eq!(
        PublicKey::<Group2048>::try_from(key.to_vec()).expect("owned bytes"),
        key
    );
    assert_eq!(
        PublicKey::<Group2048>::try_from(key.as_bytes()).expect("borrowed bytes"),
        key
    );
    assert_eq!(
        PublicKey::<Group2048>::try_from_hex(&key.to_string()).expect("printed hex"),
        key
    );
    assert!(format!("{key:?}").starts_with("PublicKey("));

    let json = serde_json::to_string(&key).expect("the key serializes");
    let back: PublicKey<Group2048> = serde_json::from_str(&json).expect("the key deserializes");
    assert_eq!(back, key);
}

#[test]
fn the_salt_implements_its_byte_contract() {
    let salt = Salt::try_from_hex("00ABCDEF").expect("valid hex");

    let cloned = salt.clone();
    assert_eq!(cloned, salt);
    assert_eq!(cloned.as_bytes(), salt.as_bytes());
    assert_eq!(cloned.to_vec(), salt.to_vec());
    assert_eq!(<Salt as AsRef<[u8]>>::as_ref(&salt), salt.as_bytes());
    assert_eq!(Vec::<u8>::from(salt.clone()), salt.to_vec());
    assert_eq!(Salt::from(salt.as_bytes()), salt);
    assert_eq!(Salt::from(salt.to_vec()), salt);
    assert_eq!(
        Salt::try_from_hex(&salt.to_string()).expect("printed hex"),
        salt
    );
    assert!(format!("{salt:?}").starts_with("Salt("));

    let json = serde_json::to_string(&salt).expect("the salt serializes");
    let back: Salt = serde_json::from_str(&json).expect("the salt deserializes");
    assert_eq!(back, salt);
}

#[test]
fn the_proof_implements_its_byte_contract() {
    let proof = Proof::try_from_hex(&"00".repeat(HASH_LENGTH)).expect("valid proof");
    let cloned = proof;

    assert_eq!(cloned, proof);
    assert_eq!(cloned.as_bytes(), proof.as_bytes());
    assert_eq!(cloned.to_vec(), proof.to_vec());
    assert!(proof.ct_eq(&proof));
    assert_eq!(
        Proof::try_from_hex(&proof.to_string()).expect("printed hex"),
        proof
    );
    assert!(format!("{proof:?}").starts_with("Proof("));

    let json = serde_json::to_string(&proof).expect("the proof serializes");
    let back: Proof = serde_json::from_str(&json).expect("the proof deserializes");
    assert_eq!(back, proof);
}

#[test]
fn the_strong_session_key_implements_its_byte_contract() {
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
    let cloned = k;

    assert_eq!(cloned, k);
    assert_eq!(cloned.as_bytes(), k.as_bytes());
    assert_eq!(cloned.to_vec(), k.to_vec());
    assert_eq!(
        StrongSessionKey::from_key(*k.as_bytes()),
        k,
        "the internal key constructor keeps the same value"
    );
    assert_eq!(
        StrongSessionKey::try_from_hex(&k.to_string()).expect("printed hex"),
        k
    );
    assert!(format!("{k:?}").starts_with("StrongSessionKey("));
}

#[test]
fn the_driver_reports_the_group_widths() {
    let srp = Srp6::new(Group2048);

    assert_eq!(srp.n_bytes(), 256);
    assert_eq!(srp.salt_bytes(), 256);
}
