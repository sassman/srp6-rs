use std::fmt::Write as _;

use crate::credentials::{ClearTextPassword, Username};
use crate::group::{Group1024, GroupOps};
use crate::hash::HASH_LENGTH;
use crate::typed::{steps, FromHexString, Salt, Srp6};

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
    let mut out = String::with_capacity((bytes.len() - start) * 2);
    for byte in &bytes[start..] {
        write!(out, "{byte:02X}").expect("writing to a String cannot fail");
    }
    out
}

/// The test vectors from RFC 5054 appendix B.
#[allow(non_snake_case)]
#[test]
fn test_appendix_b_srp_test_vectors() {
    let username = Username::new("alice").expect("valid username");
    let password = ClearTextPassword::from("password123");
    let salt = Salt::try_from_hex("BEB25379 D1A8581E B5A72767 3A2441EE").unwrap();

    let group = Group1024;
    let helper = Group1024;
    let a = group.exponent_from_bytes(&hex_to_bytes(
        "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393",
    ));
    let b = group.exponent_from_bytes(&hex_to_bytes(
        "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20",
    ));

    let srp = Srp6::new(group);
    let (salt, verifier) =
        srp.generate_new_user_secrets_with_salt(&username, &password, salt);
    let (handshake, server) = srp
        .start_handshake_with_b(&username, salt.clone(), verifier.clone(), b)
        .expect("the handshake starts");
    let (proof, client) = srp
        .calculate_proof_with_a(&handshake, &username, &password, a)
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&server, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&client, &m2)
        .expect("the strong proof verifies");

    let x = steps::private_key_x(&helper, &username, &password, &salt);
    assert_eq!(
        hex_trimmed(&helper.exponent_to_bytes(&x)),
        "94B7555AABE9127CC58CCF4993DB6CF84D16C124",
        "private key x"
    );

    assert_eq!(
        hex_trimmed(verifier.as_bytes()),
        "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB",
        "password verifier v"
    );

    assert_eq!(
        hex_trimmed(proof.A.as_bytes()),
        "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B",
        "public key A"
    );

    assert_eq!(
        hex_trimmed(handshake.B.as_bytes()),
        "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58",
        "public key B"
    );

    let u = steps::scrambler_u(&helper, &proof.A, &handshake.B);
    assert_eq!(
        hex_trimmed(&helper.exponent_to_bytes(&u)),
        "CE38B9593487DA98554ED47D70A7AE5F462EF019",
        "scrambler u"
    );

    let v_field = verifier
        .to_field(&helper)
        .expect("a validated field element");
    let a_field = proof
        .A
        .to_field(&helper)
        .expect("a validated field element");
    let s_host = helper.field_pow(
        &helper.field_mul(&a_field, &helper.field_pow(&v_field, &u)),
        &b,
    );
    assert_eq!(
        hex_trimmed(&helper.field_to_bytes(&s_host)),
        "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A",
        "session key S"
    );

    assert_eq!(
        proof.M1.as_bytes().len(),
        HASH_LENGTH,
        "M1 is one hash long"
    );
    assert_eq!(m2.as_bytes().len(), HASH_LENGTH, "M2 is one hash long");
    assert_eq!(k.as_bytes().len(), 2 * HASH_LENGTH, "K is two hashes long");
}
