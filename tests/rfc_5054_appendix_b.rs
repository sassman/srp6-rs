use std::convert::TryFrom;

use srp6::prelude::*;

mod rfc_5054_appendix_a;
use rfc_5054_appendix_a::group_1024_bit;

/// This test is based on the test vectors from [RFC5054 Appendix B](https://datatracker.ietf.org/doc/html/rfc5054#appendix-B)
#[allow(non_snake_case)]
#[test]
fn test_appendix_b_srp_test_vectors() {
    /// this is all based on sha1, that is why the length is 32
    const N_BYTE_LEN: usize = 1024 / 8;

    let I = Username::from("alice");
    let P = ClearTextPassword::from("password123");
    let s = Salt::from_hex_str_be("BEB25379 D1A8581E B5A72767 3A2441EE").unwrap();
    const SALT_LENGTH: usize = 16;
    assert_eq!(SALT_LENGTH, s.num_bytes(), "Salt length is not correct");

    let N = group_1024_bit::N();
    let g = group_1024_bit::g();

    let k = MultiplierParameter::from_hex_str_be("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")
        .unwrap();
    let x = PrivateKey::from_hex_str_be("94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124").unwrap();
    let v = PasswordVerifier::from_hex_str_be(
        "7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
         9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
         C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
         EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
         E955A5E2 9E7AB245 DB2BE315 E2099AFB",
    )
    .unwrap();

    assert_eq!(
        calculate_private_key_x(&I, &P, &s),
        x,
        "Private key x was not calculated correctly"
    );

    assert_eq!(
        calculate_password_verifier_v(&N, &g, &x),
        v,
        "Password verifiert v was not calculated correctly"
    );

    let a = PrivateKey::try_from(
        "60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD
         DA2D4393",
    )
    .unwrap();

    let A = PublicKey::try_from(
        "61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
         4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
         8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
         BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
         B349EF5D 76988A36 72FAC47B 0769447B",
    )
    .unwrap();

    assert_eq!(
        calculate_pubkey_A(&N, &g, &a),
        A,
        "Public key A was not calculated correctly"
    );

    let b = PrivateKey::try_from(
        "E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1
         05284D20",
    )
    .unwrap();

    let B = PublicKey::try_from(
        "BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
         BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
         6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
         37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
         EB4012B7 D7665238 A8E3FB00 4B117B58",
    )
    .unwrap();

    assert_eq!(
        calculate_pubkey_B(&N, &k, &g, &v, &b),
        B,
        "Public key B was not calculated correctly"
    );

    let u = hex_literal::hex!("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019");

    assert_eq!(
        calculate_u::<N_BYTE_LEN>(&A, &B).to_vec(),
        u,
        "u was not calculated correctly"
    );

    let premaster_secret = BigNumber::try_from(
        "B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
         233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
         41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
         3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
         C346D7E4 74B29EDE 8A469FFE CA686E5A",
    )
    .unwrap();

    let session_key_host =
        calculate_session_key_S_for_host::<N_BYTE_LEN>(&N, &A, &B, &b, &v).unwrap();
    assert_eq!(
        session_key_host, premaster_secret,
        "Session key host is not correct"
    );

    let session_key_client =
        calculate_session_key_S_for_client::<N_BYTE_LEN>(&N, &k, &g, &B, &A, &a, &x).unwrap();
    assert_eq!(
        session_key_client, premaster_secret,
        "Session key client is not correct"
    );
}
