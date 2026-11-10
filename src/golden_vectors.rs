//! Golden vectors for the SRP6 arithmetic.
//!
//! These freeze what the current backend computes: private key, verifier,
//! public keys, session key, interleaved key and both proofs, for each group
//! and hash flavour the crate ships. Regenerate with:
//!
//! ```text
//! cargo test --lib -- --ignored regenerate_golden
//! cargo test --lib --no-default-features --features wow-1-12-1 -- --ignored regenerate_golden
//! ```
//!
//! A backend swap must keep every byte these fixtures hold.

use std::fmt::Write as _;

use crate::credentials::Username;
use crate::group::GroupOps;
#[cfg(feature = "wow-1-12-1")]
use crate::group::GroupWow;
use crate::typed::{steps, FromHexString, Salt, Srp6};

/// The RFC 5054 appendix B salt, reused here so the vectors have one fixed input.
const SALT_HEX: &str = "BEB25379D1A8581EB5A727673A2441EE";
const PRIVATE_A_HEX: &str = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393";
const PRIVATE_B_HEX: &str = "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02X}").expect("writing to a String cannot fail");
    }
    out
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    assert!(
        !bytes.is_empty() && bytes.len().is_multiple_of(2),
        "hex must have an even, non-zero number of digits"
    );
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(pair, 16).expect("valid hex")
        })
        .collect()
}

fn hex_trimmed(bytes: &[u8]) -> String {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    hex(&bytes[start..])
}

/// Everything a full handshake derives, in a stable text form.
#[allow(non_snake_case)]
fn snapshot<G: GroupOps>(group: G, username: &Username, password: &str, salt: &Salt) -> String {
    let a = group.exponent_from_bytes(&hex_to_bytes(PRIVATE_A_HEX));
    let b = group.exponent_from_bytes(&hex_to_bytes(PRIVATE_B_HEX));

    let srp = Srp6::new(group);
    let (salt, verifier) =
        srp.generate_new_user_secrets_with_salt(username, password, salt.clone());
    let (handshake, server) = srp
        .start_handshake_with_b(username, salt.clone(), verifier.clone(), b.clone())
        .expect("the handshake starts");
    let (proof, client) = srp
        .calculate_proof_with_a(&handshake, username, password, a.clone())
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&server, &proof)
        .expect("the proof verifies");
    let strong_key = srp
        .verify_strong_proof(&client, &m2)
        .expect("the strong proof verifies");

    // `x` and `S` are not public values; recompute them from the same inputs.
    let helper = G::default();
    let x = steps::private_key_x(&helper, username, password, &salt);
    let u = steps::scrambler_u(&helper, &proof.A, &handshake.B);
    let v_field = verifier
        .to_field(&helper)
        .expect("a validated field element");
    let a_field = proof
        .A
        .to_field(&helper)
        .expect("a validated field element");
    let b_field = handshake
        .B
        .to_field(&helper)
        .expect("a validated field element");
    let g_field = handshake
        .g
        .to_field(&helper)
        .expect("a validated field element");
    let k_field = handshake
        .k
        .to_field(&helper)
        .expect("a validated field element");

    let s_host = helper.field_pow(
        &helper.field_mul(&a_field, &helper.field_pow(&v_field, &u)),
        &b,
    );
    let s_client = helper.field_pow(
        &helper.field_sub(
            &b_field,
            &helper.field_mul(&k_field, &helper.field_pow(&g_field, &x)),
        ),
        &helper.exponent_add(&a, &helper.exponent_mul(&u, &x)),
    );
    assert_eq!(
        helper.field_to_bytes(&s_host),
        helper.field_to_bytes(&s_client),
        "both sides must derive the same S"
    );

    let mut out = String::new();
    writeln!(out, "x = {}", hex_trimmed(&helper.exponent_to_bytes(&x)))
        .expect("writing to a String cannot fail");
    writeln!(out, "v = {}", hex_trimmed(verifier.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "A = {}", hex_trimmed(proof.A.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "B = {}", hex_trimmed(handshake.B.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "S = {}", hex_trimmed(&helper.field_to_bytes(&s_host)))
        .expect("writing to a String cannot fail");
    writeln!(out, "K = {}", hex_trimmed(strong_key.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "M1 = {}", hex_trimmed(proof.M1.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "M2 = {}", hex_trimmed(m2.as_bytes())).expect("writing to a String cannot fail");
    out
}

fn salt() -> Salt {
    Salt::try_from_hex(SALT_HEX).expect("valid hex")
}

#[cfg(not(feature = "hash-sha1"))]
fn vectors_2048_sha512() -> String {
    snapshot(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(not(feature = "hash-sha1"))]
fn vectors_4096_sha512() -> String {
    snapshot(
        crate::group::Group4096,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(all(feature = "hash-sha1", not(feature = "wow-1-12-1")))]
fn vectors_2048_sha1() -> String {
    snapshot(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(feature = "wow-1-12-1")]
fn vectors_wow_sha1() -> String {
    snapshot(
        GroupWow,
        &Username::new("Thrall").expect("valid username"),
        "thrall",
        &salt(),
    )
}

fn check(expected: &str, actual: &str) {
    // Git may check the fixture out with CRLF; compare line endings by content.
    let expected = expected.replace("\r\n", "\n");
    assert_eq!(expected.trim(), actual.trim());
}

#[cfg(not(feature = "hash-sha1"))]
#[test]
fn golden_2048_sha512() {
    check(
        include_str!("../tests/golden/2048-sha512.txt"),
        &vectors_2048_sha512(),
    );
}

#[cfg(not(feature = "hash-sha1"))]
#[test]
fn golden_4096_sha512() {
    check(
        include_str!("../tests/golden/4096-sha512.txt"),
        &vectors_4096_sha512(),
    );
}

#[cfg(all(feature = "hash-sha1", not(feature = "wow-1-12-1")))]
#[test]
fn golden_2048_sha1() {
    check(
        include_str!("../tests/golden/2048-sha1.txt"),
        &vectors_2048_sha1(),
    );
}

#[cfg(feature = "wow-1-12-1")]
#[test]
fn golden_wow_sha1() {
    check(
        include_str!("../tests/golden/wow-sha1.txt"),
        &vectors_wow_sha1(),
    );
}

/// A session key whose least significant byte is zero must still interleave
/// the same way. This is the case the old padding arm gets right by accident
/// and the WoW client's strip-zeros arm treats explicitly.
#[cfg(not(feature = "hash-sha1"))]
#[test]
fn interleave_pads_a_session_key_with_a_zero_low_byte() {
    let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");

    let k = steps::strong_session_key_bytes(&s);

    assert_eq!(
        hex_trimmed(k.as_bytes()),
        include_str!("../tests/golden/interleave-zero-low-byte-sha512.txt").trim()
    );
}

#[cfg(feature = "hash-sha1")]
#[test]
fn interleave_pads_a_session_key_with_a_zero_low_byte() {
    let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");

    let k = steps::strong_session_key_bytes(&s);

    assert_eq!(
        hex_trimmed(k.as_bytes()),
        include_str!("../tests/golden/interleave-zero-low-byte-sha1.txt").trim()
    );
}

#[test]
#[ignore = "regenerates the golden fixtures; run with --ignored"]
fn regenerate_golden() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");

    #[cfg(not(feature = "hash-sha1"))]
    {
        std::fs::write(format!("{dir}/2048-sha512.txt"), vectors_2048_sha512()).unwrap();
        std::fs::write(format!("{dir}/4096-sha512.txt"), vectors_4096_sha512()).unwrap();

        let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");
        let k = steps::strong_session_key_bytes(&s);
        std::fs::write(
            format!("{dir}/interleave-zero-low-byte-sha512.txt"),
            hex_trimmed(k.as_bytes()),
        )
        .unwrap();
    }

    #[cfg(feature = "hash-sha1")]
    {
        let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");
        let k = steps::strong_session_key_bytes(&s);
        std::fs::write(
            format!("{dir}/interleave-zero-low-byte-sha1.txt"),
            hex_trimmed(k.as_bytes()),
        )
        .unwrap();
    }

    #[cfg(all(feature = "hash-sha1", not(feature = "wow-1-12-1")))]
    {
        std::fs::write(format!("{dir}/2048-sha1.txt"), vectors_2048_sha1()).unwrap();
    }

    #[cfg(feature = "wow-1-12-1")]
    {
        std::fs::write(format!("{dir}/wow-sha1.txt"), vectors_wow_sha1()).unwrap();
    }
}
