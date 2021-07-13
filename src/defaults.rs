/*!
default prime modulus and generator numbers taken from [RFC5054 Appendix A],
so they can be treated as vetted and safe.

## Usage:
```rust
use srp6::{Srp6_4096, HostAPI};

let srp = Srp6_4096::default();
let (_salt_s, _verifier_v) = srp.generate_new_user_secrets("Bob", "secret-password");
```

**NOTE:** if you need to roll your own modulus, you can generate one e.g. like this:
```sh
openssl genrsa 1024 | openssl rsa -modulus
```

then you can alias a type for a convienice e.g.:
```rust
use srp6::{Srp6, Generator, TryInto};

pub type MyCustomSrp6 = Srp6<2, 2>;
pub fn my_custom_srp6_new() -> MyCustomSrp6 {
    MyCustomSrp6::new(
        Generator::from(5),
        "FE27".try_into().unwrap(),
    ).unwrap()
}

let my_srp = my_custom_srp6_new();
```

[RFC5054 Appendix A]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A
*/

use crate::api::host::Srp6;
use crate::primitives::Generator;

use hex_literal::hex;
use std::convert::TryInto;

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 256 bit / 32 byte.
#[cfg(feature = "legacy")]
pub type Srp6_256 = Srp6<32, 32>;
#[cfg(feature = "legacy")]
impl Default for Srp6_256 {
    fn default() -> Self {
        Self::new(
            Generator::from(7),
            "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
                .try_into()
                .unwrap(),
        )
        .unwrap()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 512 bit / 64 byte.
#[cfg(feature = "legacy")]
pub type Srp6_512 = Srp6<64, 64>;
#[cfg(feature = "legacy")]
impl Default for Srp6_512 {
    fn default() -> Self {
        Self::new(
            Generator::from(7),
            "D58B60A281533E85DA01C6943F8EAF5A14737F8F701788B4611A3A88D5A6A0A0E3EA3DA917EF8D036BA79706DAC9EB261E469D02B44998B88F3B06EACFF96D7B"
                .try_into()
                .unwrap()
        ).unwrap()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 1024 bit / 128 byte.
/// taken from the 1024-bit group at [RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
#[cfg(feature = "legacy")]
pub type Srp6_1024 = Srp6<128, 128>;
#[cfg(feature = "legacy")]
impl Default for Srp6_1024 {
    fn default() -> Self {
        Self::new(
            Generator::from(2),
            Generator::from_bytes_be (&hex!("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B 9FC61D2F C0EB06E3"))
        ).unwrap()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 2048 bit / 256 byte.
/// taken from the 2048-bit group at [RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
pub type Srp6_2048 = Srp6<256, 256>;
impl Default for Srp6_2048 {
    fn default() -> Self {
        Self::new(
            Generator::from(7),
            "93BE8A2C0FAC7442480A9253539E32A6DE3C3F33D4B7DB4431344F41CAA975E28B626D23E553FCB1450850777ED260D2FFE1FB9816A6ED7164CD76D05733DE4EFA931514D008B7EA8A4BAC45AB7DFD8C346B924E04C37420EEAFCD486159FB49A236DC77B6884FBF3907F0AB8ED789692BA424C81E35A61A38C72EC3A7268B069FCBFBC236AA3167A11E1FD5CD1275021BAC8493CA3AAEBF4AEF685E93A0387C10861F8DB1C500D3DE1823D905EAB421D1E0FD92CEE61F44FF439D07388F1BA56DA112589878D565A199A3C27630DA8FAD31E07EE0A46269B302F215DD972CF9E746867F608DA4DA28A69399708FADC795A6B16276EB6EF5A90636D86DAF03A5"
                .try_into()
                .unwrap()
        ).unwrap()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 4096 bit / 512 byte.
/// taken from the 4096-bit group at [RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
pub type Srp6_4096 = Srp6<512, 512>;
impl Default for Srp6_4096 {
    fn default() -> Self {
        Self::new(
            Generator::from(5),
            Generator::from_bytes_be(&hex!(
                "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
                 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
                 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
                 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
                 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
                 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
                 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
                 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
                 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
                 04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
                 B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
                 1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
                 BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
                 E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
                 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
                 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
                 233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
                 D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
                 FFFFFFFF FFFFFFFF"
            )),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "legacy")]
    fn should_ensure_key_length_is_as_expected() {
        let srp = Srp6_256::default();
        assert_eq!(srp.N.num_bytes(), 256 / 8);

        let srp = Srp6_512::default();
        assert_eq!(srp.N.num_bytes() as u32, 512 / 8);

        let srp = Srp6_1024::default();
        assert_eq!(srp.N.num_bytes() as u32, 1024 / 8);
    }

    #[test]
    fn should_ensure_the_non_legacy_key_lengths() {
        let srp = Srp6_2048::default();
        assert_eq!(srp.N.num_bytes() as u32, 2048 / 8);

        let srp = Srp6_4096::default();
        assert_eq!(srp.N.num_bytes() as u32, 4096 / 8);
    }
}
