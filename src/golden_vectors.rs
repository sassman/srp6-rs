//! Golden vectors for the SRP6 arithmetic.
//!
//! These freeze what the current backend computes: private key, verifier,
//! public keys, session key, interleaved key and both proofs, for each group
//! and hash flavour the crate ships. Regenerate with:
//!
//! ```text
//! cargo test --test golden_vectors -- --ignored regenerate_golden
//! cargo test --test golden_vectors --no-default-features --features wow-1-12-1 -- --ignored regenerate_golden
//! ```
//!
//! A backend swap must keep every byte these fixtures hold.

use std::fmt::Write as _;

use crate::big_number::BigNumber;
use crate::credentials::Username;
use crate::group::Group;
#[cfg(feature = "wow-1-12-1")]
use crate::group::GroupWow;
use crate::primitives::*;

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

/// Everything a full handshake derives, in a stable text form.
#[allow(non_snake_case)]
fn snapshot<G: Group, const N_BYTE_LEN: usize, const SALT_LENGTH: usize>(
    group: G,
    username: &Username,
    password: &str,
    salt: &Salt,
) -> String {
    let N = PrimeModulus::from_bytes_be(&group.modulus_bytes());
    let g = Generator::from_bytes_be(&group.generator_bytes());
    let k_multiplier = Generator::from_bytes_be(&group.multiplier_bytes());

    let x = calculate_private_key_x(username, password, salt);
    let v = calculate_password_verifier_v(&N, &g, &x);
    let a = PrivateKey::from_hex_str_be(PRIVATE_A_HEX).expect("valid hex");
    let b = PrivateKey::from_hex_str_be(PRIVATE_B_HEX).expect("valid hex");

    let A = calculate_pubkey_A(&N, &g, &a).expect("A is not 0 mod N");
    let B = calculate_pubkey_B(&N, &k_multiplier, &g, &v, &b).expect("B is not 0 mod N");

    let s_host =
        calculate_session_key_S_for_host::<N_BYTE_LEN>(&N, &A, &B, &b, &v).expect("valid A");
    let s_client =
        calculate_session_key_S_for_client::<N_BYTE_LEN>(&N, &k_multiplier, &g, &B, &A, &a, &x)
            .expect("valid B");
    assert_eq!(s_host, s_client, "both sides must derive the same S");

    let k = calculate_session_key_hash_interleave_K::<N_BYTE_LEN>(&s_host);
    let m1 = calculate_proof_M::<N_BYTE_LEN, SALT_LENGTH>(&N, &g, username, salt, &A, &B, &k);
    let m2 = calculate_strong_proof_M2::<N_BYTE_LEN>(&A, &m1, &k);

    let mut out = String::new();
    writeln!(out, "x = {}", hex(&x.to_vec())).expect("writing to a String cannot fail");
    writeln!(out, "v = {}", hex(&v.to_vec())).expect("writing to a String cannot fail");
    writeln!(out, "A = {}", hex(&A.to_vec())).expect("writing to a String cannot fail");
    writeln!(out, "B = {}", hex(&B.to_vec())).expect("writing to a String cannot fail");
    writeln!(out, "S = {}", hex(&s_host.to_vec())).expect("writing to a String cannot fail");
    writeln!(out, "K = {}", hex(&k.to_vec())).expect("writing to a String cannot fail");
    writeln!(out, "M1 = {}", hex(&m1.to_vec())).expect("writing to a String cannot fail");
    writeln!(out, "M2 = {}", hex(&m2.to_vec())).expect("writing to a String cannot fail");
    out
}

fn salt() -> Salt {
    Salt::from_hex_str_be(SALT_HEX).expect("valid hex")
}

#[cfg(not(feature = "hash-sha1"))]
fn vectors_2048_sha512() -> String {
    snapshot::<crate::group::Group2048, 256, 256>(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(not(feature = "hash-sha1"))]
fn vectors_4096_sha512() -> String {
    snapshot::<crate::group::Group4096, 512, 512>(
        crate::group::Group4096,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(all(feature = "hash-sha1", not(feature = "wow-1-12-1")))]
fn vectors_2048_sha1() -> String {
    snapshot::<crate::group::Group2048, 256, 256>(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(feature = "wow-1-12-1")]
fn vectors_wow_sha1() -> String {
    snapshot::<GroupWow, 32, 32>(
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
    let s = SessionKey::from_hex_str_be(
        "00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788",
    )
    .expect("valid hex");

    let k = calculate_session_key_hash_interleave_K::<32>(&s);

    assert_eq!(
        hex(&k.to_vec()),
        include_str!("../tests/golden/interleave-zero-low-byte-sha512.txt").trim()
    );
}

#[cfg(feature = "hash-sha1")]
#[test]
fn interleave_pads_a_session_key_with_a_zero_low_byte() {
    let s = SessionKey::from_hex_str_be(
        "00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788",
    )
    .expect("valid hex");

    let k = calculate_session_key_hash_interleave_K::<32>(&s);

    assert_eq!(
        hex(&k.to_vec()),
        include_str!("../tests/golden/interleave-zero-low-byte-sha1.txt").trim()
    );
}

/// The text formats the migration must keep: blocked hex, JSON, and the
/// zero-padded array.
#[test]
fn text_and_byte_formats_do_not_move() {
    let value = BigNumber::from_hex_str_be("BEB25379 D1A8581E B5A72767 3A2441EE").unwrap();
    assert_eq!(
        value,
        Salt::from_hex_str_be("BEB25379D1A8581EB5A727673A2441EE").unwrap()
    );
    let padded = value.to_array_pad_zero::<32>();
    assert_eq!(padded.len(), 32);
    assert_eq!(&padded[..16], &[0_u8; 16]);
    assert_eq!(&padded[16..], value.to_vec().as_slice());

    let json = serde_json::to_string(&value).unwrap();
    let back: BigNumber = serde_json::from_str(&json).unwrap();
    assert_eq!(value, back);
}

#[test]
#[ignore = "regenerates the golden fixtures; run with --ignored"]
fn regenerate_golden() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");

    #[cfg(not(feature = "hash-sha1"))]
    {
        std::fs::write(format!("{dir}/2048-sha512.txt"), vectors_2048_sha512()).unwrap();
        std::fs::write(format!("{dir}/4096-sha512.txt"), vectors_4096_sha512()).unwrap();

        let s = SessionKey::from_hex_str_be(
            "00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788",
        )
        .unwrap();
        std::fs::write(
            format!("{dir}/interleave-zero-low-byte-sha512.txt"),
            hex(&calculate_session_key_hash_interleave_K::<32>(&s).to_vec()),
        )
        .unwrap();
    }

    #[cfg(feature = "hash-sha1")]
    {
        let s = SessionKey::from_hex_str_be(
            "00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788",
        )
        .unwrap();
        std::fs::write(
            format!("{dir}/interleave-zero-low-byte-sha1.txt"),
            hex(&calculate_session_key_hash_interleave_K::<32>(&s).to_vec()),
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
