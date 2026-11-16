use std::convert::TryFrom;

use super::*;
use crate::credentials::Username;
use crate::group::{Group, Group2048, Group4096, GroupOps};
use crate::hash::{DefaultHash, Digest, HashFor};
use crate::Srp6Error;
use crate::Srp6_2048;

#[cfg(feature = "wow-1-12-1")]
use crate::group::GroupWow;
#[cfg(feature = "wow-1-12-1")]
use crate::wow::Srp6_256;

fn round_trip<G: GroupOps, H: HashFor<G>>(group: G) {
    let srp = Srp6::<G, H>::new(group);
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let ServerProof {
        strong_proof: m2,
        session_key: server_key,
    } = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let client_key = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");
    assert_eq!(server_key, client_key, "both sides derive the same K");
}

#[test]
fn a_2048_bit_handshake_round_trips() {
    round_trip::<_, DefaultHash>(Group2048);
}

#[test]
fn a_4096_bit_handshake_round_trips() {
    round_trip::<_, DefaultHash>(Group4096);
}

#[cfg(feature = "wow-1-12-1")]
#[test]
fn a_wow_handshake_round_trips() {
    round_trip::<_, crate::hash::Sha1>(GroupWow);
}

/// When a value such as `A`, `K` or `M1` happens to have a zero high-order byte
/// (about 1 in 256 per value), there are two ways to hash it: at the full fixed
/// width, or with the zero stripped. The 1.12.1 client does the first, vmangos
/// does the second, so they compute different hashes and a correct password is
/// refused. Redrawing the ephemeral simply avoids the values where the two
/// disagree.
///
/// A draw `calculate_proof` makes itself is redrawn, so a caller never sees
/// `AmbiguousEncoding` from it. Without the redraw a run this long would hit an
/// ambiguous draw almost surely.
///
/// Caution: this is rejection sampling, not a uniform draw - it excludes
/// ephemerals whose derived values would hash ambiguously, trading a sliver of
/// `a`'s theoretical uniformity for the stock client's buggy fixed-width hash.
/// The margin is far below any practical attack, and exists only behind the
/// `wow-1-12-1` feature this legacy interop is gated on.
#[cfg(feature = "wow-1-12-1")]
#[test]
fn a_drawn_wow_proof_is_never_ambiguous() {
    let srp = Srp6_256::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, _) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");

    for _ in 0..400 {
        let ClientProof { proof, verifier } = srp
            .calculate_proof(&handshake, &username, "password123")
            .expect("an ambiguous draw is redrawn, not reported");
        assert_ne!(proof.public_key().as_bytes().last(), Some(&0), "A");
        assert_ne!(verifier.session_key().as_bytes().last(), Some(&0), "K");
        assert_ne!(proof.proof().as_bytes().last(), Some(&0), "M1");
    }
}

#[test]
fn a_wrong_password_is_refused() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof { proof, verifier: _ } = srp
        .calculate_proof(&handshake, &username, "wrong")
        .expect("the client can prove");
    assert!(srp.verify_proof(&proof_verifier, &proof).is_err());
}

#[test]
fn a_zero_premaster_from_a_malicious_server_is_refused() {
    let srp = Srp6_2048::default();
    let group = Group2048;
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");

    // A malicious server sends B = k*v, so base = B - k*g^x = k*(v - g^x) = 0
    // and the premaster S collapses to zero (B itself is still non-zero, so it
    // passes the public-key check).
    let k = super::steps::multiplier::<_, DefaultHash>(&group);
    let v = verifier.to_field(&group).expect("verifier field");
    let b_field = group.field_mul(&k, &v);
    let handshake = Handshake {
        B: PublicKey::from_field(&group, &b_field),
        s: salt,
    };

    assert!(matches!(
        srp.calculate_proof(&handshake, &username, "password123"),
        Err(crate::Srp6Error::InvalidPremaster)
    ));
}

#[test]
fn a_wrong_strong_proof_is_refused() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let ServerProof {
        strong_proof: m2, ..
    } = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");

    let mut wrong = m2.to_vec();
    wrong[0] ^= 1;
    let wrong = Proof::try_from_bytes(&wrong).expect("one proof width");

    assert!(srp.verify_strong_proof(&strong_verifier, &wrong).is_err());
}

#[test]
fn a_verifier_round_trips_through_its_bytes() {
    let srp = Srp6_2048::default();
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
    let short = vec![0_u8; <DefaultHash as Digest>::output_size() - 1];
    assert!(Proof::<DefaultHash>::try_from_bytes(&short).is_err());
}

#[test]
fn hex_round_trips_through_the_boundary_types() {
    let srp = Srp6_2048::default();
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
    assert!(Proof::<DefaultHash>::try_from_hex("00").is_err());
    assert!(Verifier::<Group2048>::try_from_hex("00").is_err());
}

#[test]
fn the_boundary_types_round_trip_through_json() {
    let salt = Salt::try_from_hex("00AB").expect("valid hex");
    let json = serde_json::to_string(&salt).expect("the salt serializes");
    let back: Salt = serde_json::from_str(&json).expect("the salt deserializes");
    assert_eq!(salt, back);

    let proof =
        Proof::<DefaultHash>::try_from_hex(&"00".repeat(<DefaultHash as Digest>::output_size()))
            .expect("valid proof");
    let json = serde_json::to_string(&proof).expect("the proof serializes");
    let back: Proof<DefaultHash> = serde_json::from_str(&json).expect("the proof deserializes");
    assert_eq!(proof, back);
}

#[test]
fn the_strong_session_key_round_trips_through_hex() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let ServerProof {
        strong_proof: m2, ..
    } = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");

    assert_eq!(
        StrongSessionKey::<DefaultHash>::try_from_hex(&k.to_string()).unwrap(),
        k
    );
    assert!(StrongSessionKey::<DefaultHash>::try_from_hex("00").is_err());
}

#[test]
fn the_strong_session_key_is_two_hashes_wide() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let ServerProof {
        strong_proof: m2, ..
    } = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");

    assert_eq!(
        k.as_bytes().len(),
        2 * <DefaultHash as Digest>::output_size()
    );
    assert_eq!(k, strong_verifier.K);
}

#[test]
fn the_handshake_accessors_expose_the_same_values() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");

    assert_eq!(handshake.public_key(), &handshake.B);
    assert_eq!(handshake.salt(), &handshake.s);

    assert_eq!(proof_verifier.public_key(), &proof_verifier.B);
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
    let srp = Srp6_2048::default();
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
    assert!(format!("{verifier:?}").starts_with("Verifier("));

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
    let proof =
        Proof::<DefaultHash>::try_from_hex(&"00".repeat(<DefaultHash as Digest>::output_size()))
            .expect("valid proof");
    let cloned = proof.clone();

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
    let back: Proof<DefaultHash> = serde_json::from_str(&json).expect("the proof deserializes");
    assert_eq!(back, proof);
}

#[test]
fn the_strong_session_key_implements_its_byte_contract() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");
    let ServerProof {
        strong_proof: m2, ..
    } = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");
    let cloned = k.clone();

    assert_eq!(cloned, k);
    assert_eq!(cloned.as_bytes(), k.as_bytes());
    assert_eq!(cloned.to_vec(), k.to_vec());
    assert_eq!(
        StrongSessionKey::from_key(k.to_vec()),
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
fn the_session_key_debug_does_not_leak_the_secret() {
    let hex = "AB".repeat(2 * <DefaultHash as Digest>::output_size());
    let k = StrongSessionKey::<DefaultHash>::try_from_hex(&hex).expect("valid key");

    // Display still exposes the hex on explicit request; Debug must not.
    assert_eq!(k.to_string(), hex);
    assert!(!format!("{k:?}").contains("AB"));
}

#[test]
fn the_proof_debug_does_not_leak_the_value() {
    let hex = "AB".repeat(<DefaultHash as Digest>::output_size());
    let proof = Proof::<DefaultHash>::try_from_hex(&hex).expect("valid proof");

    assert_eq!(proof.to_string(), hex);
    assert!(!format!("{proof:?}").contains("AB"));
}

#[test]
fn the_verifier_debug_does_not_leak_the_secret() {
    let hex = "AB".repeat(Group2048::N_BYTES);
    let verifier = Verifier::<Group2048>::try_from_hex(&hex).expect("valid verifier");

    assert_eq!(verifier.to_string(), hex);
    assert!(!format!("{verifier:?}").contains("AB"));
}

#[test]
fn the_driver_reports_the_group_widths() {
    let srp = Srp6_2048::default();

    assert_eq!(srp.n_bytes(), 256);
    assert_eq!(srp.salt_bytes(), 16);
}

#[test]
fn with_salt_overrides_the_generated_width() {
    let username = Username::new("alice").expect("valid username");
    let srp = Srp6_2048::default().with_salt(SaltBytes::BYTES_32);

    let (salt, _) = srp.generate_new_user_secrets(&username, "password123");

    assert_eq!(srp.salt_bytes(), 32);
    assert_eq!(salt.as_bytes().len(), 32);
}

#[test]
fn a_custom_salt_width_is_bounds_checked() {
    assert_eq!(SaltBytes::custom(16), Ok(SaltBytes::BYTES_16));
    assert!(SaltBytes::custom(8).is_ok());
    assert!(SaltBytes::custom(255).is_ok());

    for out_of_range in [0, 7, 256] {
        assert_eq!(
            SaltBytes::custom(out_of_range),
            Err(crate::Srp6Error::InvalidSaltLength {
                given: out_of_range,
                min: 8,
                max: 255,
            })
        );
    }
}

#[test]
fn a_custom_salt_width_drives_generation() {
    let username = Username::new("alice").expect("valid username");
    let width = SaltBytes::custom(255).expect("within the wire cap");
    let srp = Srp6_2048::default().with_salt(width);

    let (salt, _) = srp.generate_new_user_secrets(&username, "password123");

    assert_eq!(salt.as_bytes().len(), 255);
}

#[cfg(feature = "wow-1-12-1")]
#[test]
fn the_wow_group_defaults_to_its_wire_width() {
    assert_eq!(Srp6_256::default().salt_bytes(), 32);
}

/// A client rebuilds the handshake from the challenge bytes the server sent,
/// and a server rebuilds the proof from the answer - neither side holds the
/// other's structs, only wire bytes.
#[test]
fn both_boundary_structs_rebuild_from_wire_parts() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");

    // What the challenge carries of the handshake: B and s.
    let rebuilt = Handshake::from_wire(
        PublicKey::try_from_bytes(handshake.public_key().as_bytes()).expect("B decodes"),
        handshake.salt().clone(),
    );
    assert_eq!(rebuilt.public_key(), handshake.public_key());

    // The client proves against the rebuilt handshake; the server rebuilds the
    // proof from wire bytes and the flow still closes.
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&rebuilt, &username, "password123")
        .expect("the client can prove");
    let wire_a = proof.public_key().to_vec();
    let wire_m1 = proof.proof().to_vec();
    let proof = HandshakeProof::from_wire(
        PublicKey::try_from_bytes(&wire_a).expect("A decodes"),
        Proof::try_from_bytes(&wire_m1).expect("M1 decodes"),
    );
    let ServerProof {
        strong_proof: m2, ..
    } = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    srp.verify_strong_proof(&strong_verifier, &m2)
        .expect("the strong proof verifies");
}

/// Consumers keep these structs in their own `#[derive(Debug)]` state; the
/// impls must exist, and what is secret must not reach the log line.
#[test]
fn handshake_structs_debug_without_leaking_secrets() {
    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let ClientProof {
        proof,
        verifier: strong_verifier,
    } = srp
        .calculate_proof(&handshake, &username, "password123")
        .expect("the client can prove");

    let printed = format!("{handshake:?} {proof_verifier:?} {proof:?} {strong_verifier:?}");
    assert!(printed.contains("Handshake"));
    let b_public = handshake.public_key().to_string();
    assert!(printed.contains(&b_public), "public values stay readable");
    assert!(printed.contains("<redacted>"), "secrets are redacted");
    assert!(
        !printed.contains(&strong_verifier.session_key().to_string()),
        "the session key never reaches a log line"
    );
}

/// A server that knows no verifier could fix the premaster secret if the client
/// computed with a generator it was sent: `g = 1` makes `g^x` one for every password.
/// The handshake has no slot for a peer's group, and a wire that names one is checked
/// against the client's own.
#[test]
fn a_group_a_peer_names_is_checked_against_the_clients_own() {
    let srp = Srp6_2048::default();
    let n = srp.modulus();
    let g = srp.generator();

    assert_eq!(srp.check_group(n.as_bytes(), g.as_bytes()), Ok(()));
    assert_eq!(srp.check_group(n.as_bytes(), &[2]), Ok(()), "minimal g");

    let mut other_n = n.to_vec();
    other_n[Group2048::N_BYTES - 1] ^= 2;
    for (modulus, generator) in [
        (n.as_bytes(), &[1_u8][..]),
        (n.as_bytes(), &[][..]),
        (n.as_bytes(), &[0_u8; 257][..]),
        (other_n.as_slice(), g.as_bytes()),
        (&n.as_bytes()[1..], g.as_bytes()),
    ] {
        assert_eq!(
            srp.check_group(modulus, generator),
            Err(Srp6Error::GroupMismatch)
        );
    }
}

/// A caller's ephemeral is validated where it is built, so one that would overflow the
/// exponent, or that is zero and gives `A = 1`, never reaches a handshake.
#[test]
fn a_supplied_ephemeral_must_fit_the_group_and_not_be_zero() {
    for bad in [
        vec![],
        vec![0_u8; 32],
        vec![0xFF_u8; Group2048::N_BYTES + 1],
    ] {
        assert_eq!(
            ClientEphemeral::<Group2048>::try_from_bytes(&bad).err(),
            Some(Srp6Error::InvalidEphemeral {
                max: Group2048::N_BYTES
            }),
            "{} bytes",
            bad.len()
        );
    }

    let srp = Srp6_2048::default();
    let username = Username::new("alice").expect("valid username");
    let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let (handshake, proof_verifier) = srp
        .start_handshake(&username, salt, verifier)
        .expect("the handshake starts");
    let a = ClientEphemeral::try_from_bytes(&[0xFF_u8; Group2048::N_BYTES]).expect("fits");
    assert!(!format!("{a:?}").contains("255"), "the draw is not printed");
    let ClientProof { proof, .. } = srp
        .calculate_proof_with_a(&handshake, &username, "password123", &a)
        .expect("the client can prove");
    assert!(srp.verify_proof(&proof_verifier, &proof).is_ok());
    let _ = ClientEphemeral::<Group2048>::random();
}

/// The fixed arrays and the minimal form are views of the same bytes, so a caller that
/// knows its group needs neither a length check nor a trim of its own.
#[test]
fn a_group_value_reads_as_a_fixed_array_and_in_its_minimal_form() {
    let srp = Srp6_2048::default();
    let g = srp.generator();

    let array: [u8; 256] = g.as_array();
    assert_eq!(&array[..], g.as_bytes());
    assert_eq!(g.as_minimal_bytes(), &[2]);

    let n: [u8; 256] = srp.modulus().as_array();
    assert_eq!(&n[..], srp.modulus().as_bytes());

    let username = Username::new("alice").expect("valid username");
    let (_, verifier) = srp.generate_new_user_secrets(&username, "password123");
    let v: [u8; 256] = verifier.as_array();
    assert_eq!(&v[..], verifier.as_bytes());
}

/// The high-order zeros trail in a little-endian group, so that is the end trimmed.
#[cfg(feature = "wow-1-12-1")]
#[test]
fn the_minimal_form_follows_the_groups_byte_order() {
    let g = Srp6_256::default().generator();
    assert_eq!(g.as_bytes()[0], 7);
    assert_eq!(g.as_minimal_bytes(), &[7]);
}

/// Folding the case of a credential belongs to the legacy group, not to the build: with
/// the feature on, a group that hashes verbatim still tells `Alice` from `ALICE`.
#[test]
fn an_rfc_group_hashes_credentials_as_given() {
    let srp = Srp6_2048::default();
    let salt = Salt::from(vec![7_u8; 16]);
    let verifier_of = |name: &str, password: &str| {
        let username = Username::new(name).expect("valid username");
        srp.generate_new_user_secrets_with_salt(&username, password, salt.clone())
            .1
    };

    let given = verifier_of("Alice", "Secret");
    assert_ne!(given, verifier_of("ALICE", "Secret"));
    assert_ne!(given, verifier_of("Alice", "SECRET"));
}

/// The 1.12.1 client uppercases both before it hashes, so its group does too, whatever
/// case the caller holds them in.
#[cfg(feature = "wow-1-12-1")]
#[test]
fn the_wow_group_folds_the_case_of_credentials() {
    let srp = Srp6_256::default();
    let salt = Salt::from(vec![7_u8; 32]);
    let verifier_of = |name: &str, password: &str| {
        let username = Username::new(name).expect("valid username");
        srp.generate_new_user_secrets_with_salt(&username, password, salt.clone())
            .1
    };

    assert_eq!(
        verifier_of("Alice", "Secret"),
        verifier_of("ALICE", "SECRET")
    );
}
