//! Golden vectors for the SRP6 arithmetic.
//!
//! These freeze what the current backend computes: private key, verifier,
//! public keys, session key and interleaved key, for each group and hash
//! flavour the crate ships. The proofs are pinned by length only: `M1`/`M2`
//! are crate-flavour values, not protocol vectors, and pinning their bytes
//! would churn the fixtures on every proof-formula decision. Regenerate with:
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
#[cfg(not(feature = "hash-sha1"))]
use crate::hash::DefaultHash;
use crate::hash::Digest;
#[cfg(feature = "hash-sha1")]
use crate::hash::Sha1;
use crate::typed::{steps, FromHexString, Salt, Srp6, WireStable};
#[cfg(feature = "wow-1-12-1")]
use crate::wow::Srp6_256;

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
fn snapshot<G: GroupOps + WireStable, H: Digest>(
    group: G,
    username: &Username,
    password: &str,
    salt: &Salt,
) -> String {
    let a_bytes = hex_to_bytes(PRIVATE_A_HEX);
    let a = group.exponent_from_bytes(&a_bytes);
    let b = group.exponent_from_bytes(&hex_to_bytes(PRIVATE_B_HEX));

    let srp = Srp6::<G, H>::new(group);
    let (salt, verifier) =
        srp.generate_new_user_secrets_with_salt(username, password, salt.clone());
    let (handshake, server) = srp
        .start_handshake_with_b(username, salt.clone(), verifier.clone(), b.clone())
        .expect("the handshake starts");
    let (proof, client) = srp
        .calculate_proof_with_a(&handshake, username, password, &a_bytes)
        .expect("the client can prove");
    let (m2, _) = srp
        .verify_proof(&server, &proof)
        .expect("the proof verifies");
    let strong_key = srp
        .verify_strong_proof(&client, &m2)
        .expect("the strong proof verifies");

    // `x` and `S` are not public values; recompute them from the same inputs.
    let helper = G::default();
    let x = steps::private_key_x::<_, H>(&helper, username, password, &salt);
    let u = steps::scrambler_u::<_, H>(&helper, &proof.A, &handshake.B);
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
    writeln!(out, "M1.len = {}", proof.M1.as_bytes().len())
        .expect("writing to a String cannot fail");
    writeln!(out, "M2.len = {}", m2.as_bytes().len()).expect("writing to a String cannot fail");
    out
}

fn salt() -> Salt {
    Salt::try_from_hex(SALT_HEX).expect("valid hex")
}

#[cfg(not(feature = "hash-sha1"))]
fn vectors_2048_sha512() -> String {
    snapshot::<_, DefaultHash>(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(not(feature = "hash-sha1"))]
fn vectors_4096_sha512() -> String {
    snapshot::<_, DefaultHash>(
        crate::group::Group4096,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(all(feature = "hash-sha1", not(feature = "wow-1-12-1")))]
fn vectors_2048_sha1() -> String {
    snapshot::<_, Sha1>(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(feature = "wow-1-12-1")]
fn vectors_wow_sha1() -> String {
    snapshot::<_, Sha1>(
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

/// The published WoW SRP6 verifier (wow_srp MIT corpus, also benilla's pinned
/// golden): a real 1.12.1 client derives exactly this, little-endian, for
/// `ALICE`/`PASSWORD1` with salt bytes `i*11+2`. The lib must reproduce it or no
/// stock client can log in - this is the correctness the dogfood uncovered.
#[cfg(feature = "wow-1-12-1")]
#[test]
fn wow_verifier_matches_published_corpus() {
    let salt_bytes: Vec<u8> = (0u8..32)
        .map(|i| i.wrapping_mul(11).wrapping_add(2))
        .collect();
    let srp = Srp6_256::default();
    let (_salt, verifier) = srp.generate_new_user_secrets_with_salt(
        &Username::new("ALICE").expect("valid username"),
        "PASSWORD1",
        Salt::from(salt_bytes),
    );
    assert_eq!(
        hex(verifier.as_bytes()),
        "28B837075A12B82553921D9095FA3FDCB0151C4BFC860AB97A69D0FA86A3D213",
    );
}

/// A WoW client redraws an ephemeral whose proof would not encode unambiguously.
/// Reuses benilla's SRP fixture: against this `B`/salt, `TRIPS_A` is the draw
/// benilla found trips the `A` guard and `CLEAN` trips none, so srp6 must reject
/// the first with `AmbiguousEncoding` and accept the second.
#[cfg(feature = "wow-1-12-1")]
#[test]
fn an_ambiguous_wow_draw_is_rejected_and_a_clean_one_passes() {
    use crate::typed::{Handshake, PublicKey};
    use crate::{FieldElement, Srp6Error};

    const FIXTURE_B: [u8; 32] = [
        5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119, 156, 193, 230, 11, 48, 85, 122, 159, 196,
        233, 14, 51, 88, 125, 162, 199, 236, 17, 54, 91, 128,
    ];
    const FIXTURE_SALT: [u8; 32] = [
        3, 14, 25, 36, 47, 58, 69, 80, 91, 102, 113, 124, 135, 146, 157, 168, 179, 190, 201, 212,
        223, 234, 245, 0, 11, 22, 33, 44, 55, 66, 77, 88,
    ];
    const TRIPS_A: [u8; 32] = [
        237, 250, 2, 239, 106, 197, 124, 117, 132, 5, 226, 189, 212, 217, 169, 146, 39, 212, 214,
        11, 198, 57, 225, 84, 17, 219, 168, 107, 118, 105, 11, 95,
    ];
    const CLEAN: [u8; 32] = [
        52, 226, 21, 16, 93, 106, 129, 125, 56, 197, 129, 14, 149, 1, 254, 105, 63, 23, 9, 190, 46,
        113, 240, 125, 128, 130, 150, 46, 174, 240, 93, 249,
    ];

    let srp = crate::wow::Srp6_256::default();
    let handshake = Handshake::from_wire(
        PublicKey::<GroupWow>::try_from_bytes(&FIXTURE_B).expect("B is a valid public key"),
        FieldElement::<GroupWow>::try_from_bytes(&[7]).expect("g = 7"),
        srp.multiplier(),
        Salt::from(FIXTURE_SALT.to_vec()),
    );
    let user = Username::new("alice").expect("valid username");

    assert!(
        matches!(
            srp.calculate_proof_with_a(&handshake, &user, "password1", &TRIPS_A),
            Err(Srp6Error::AmbiguousEncoding)
        ),
        "the A-tripping draw must be rejected"
    );
    // The clean draw is also a whole-handshake known answer: `A`, `M1`, `M2` and
    // `K` as benilla's own client computes them for this fixture.
    let (proof, verifier) = srp
        .calculate_proof_with_a(&handshake, &user, "password1", &CLEAN)
        .expect("the clean draw must pass");
    assert_eq!(
        hex(proof.public_key().as_bytes()),
        "35F896D3776C62F3125D4BE34A3CE13CC60A9A46354FC0ED5F2BF3C57A18D86C",
    );
    assert_eq!(
        hex(proof.proof().as_bytes()),
        "4B706EE7E19D1151451684860CBD1FCD02D71BEC",
    );
    let m2 = crate::Proof::try_from_hex("76B7DB2B48435911FB013BBF2FBE35DF69FA27E1")
        .expect("a SHA-1 proof");
    let key = srp
        .verify_strong_proof(&verifier, &m2)
        .expect("the golden M2 verifies");
    assert_eq!(
        hex(key.as_bytes()),
        "E5D5D1ED870112DB554579245BEFC674DF740DD1AAB9D42C380B73E9784EFA0A893C4816D97DF547",
    );
}

/// The published WoW session-key interleave (wow_srp MIT corpus, also benilla's
/// pinned goldens): little-endian `S` in, little-endian `K` out. Guards that the
/// lib folds `S` into `K` exactly as the real client does.
#[cfg(feature = "wow-1-12-1")]
#[test]
fn wow_interleave_matches_published_corpus() {
    let cases = [
        (
            "8F4CEBD60DFC34E5C007E51BD4F3A4FF2BC1D930E2D3EA770D8D3EEDFF2DCCFC",
            "EE144E1AE08DAC891AB63ABC42BF89738003343422E6B58131BEE4C3087A7027E55A7216D18D556C",
        ),
        (
            "CCC1BDE07FC4FA3182DDEAAB036A88F78AD605AB0D8BFBF6F5EE8ED65CDE4F09",
            "2AA23706C3FC3517A4293E2D4944F567E220CC1A227359D70154E5FD3CEE973673130C4AFBAD9E6D",
        ),
    ];
    for (s_hex, key_hex) in cases {
        let k = steps::strong_session_key_bytes::<Sha1>(&hex_to_bytes(s_hex));
        assert_eq!(hex(k.as_bytes()), key_hex, "S={s_hex}");
    }
}

/// A session key whose least significant byte is zero must still interleave
/// the same way: `S` is hashed at its fixed width, never trimmed.
#[cfg(not(feature = "hash-sha1"))]
#[test]
fn interleave_pads_a_session_key_with_a_zero_low_byte() {
    let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");

    let k = steps::strong_session_key_bytes::<DefaultHash>(&s);

    assert_eq!(
        hex_trimmed(k.as_bytes()),
        include_str!("../tests/golden/interleave-zero-low-byte-sha512.txt").trim()
    );
}

#[cfg(feature = "hash-sha1")]
#[test]
fn interleave_pads_a_session_key_with_a_zero_low_byte() {
    let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");

    let k = steps::strong_session_key_bytes::<Sha1>(&s);

    assert_eq!(
        hex_trimmed(k.as_bytes()),
        include_str!("../tests/golden/interleave-zero-low-byte-sha1.txt").trim()
    );
}

/// The capability the mutually-exclusive hash features forbade: one binary runs
/// SHA-1 and SHA-512 on the same group, as two instances, and they disagree -
/// proof the hash is a real per-instance choice.
#[cfg(feature = "hash-sha1")]
#[test]
fn one_group_runs_both_hashes_at_once() {
    use crate::group::Group2048;

    let user = Username::new("alice").expect("valid username");
    let (_s1, v_sha1) = Srp6::<Group2048, Sha1>::new(Group2048)
        .generate_new_user_secrets_with_salt(&user, "password123", salt());
    let (_s2, v_sha512) = Srp6::<Group2048, crate::hash::DefaultHash>::new(Group2048)
        .generate_new_user_secrets_with_salt(&user, "password123", salt());

    assert_ne!(v_sha1.to_vec(), v_sha512.to_vec());
    assert_eq!(
        v_sha1.as_bytes().len(),
        v_sha512.as_bytes().len(),
        "same group width"
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
        let k = steps::strong_session_key_bytes::<DefaultHash>(&s);
        std::fs::write(
            format!("{dir}/interleave-zero-low-byte-sha512.txt"),
            hex_trimmed(k.as_bytes()),
        )
        .unwrap();
    }

    #[cfg(feature = "hash-sha1")]
    {
        let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");
        let k = steps::strong_session_key_bytes::<Sha1>(&s);
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
