//! Const Montgomery parameters for the closed SRP groups.
//!
//! RFC 5054 appendix A and the 1.12.1 wow group each fix one modulus, so their
//! Montgomery parameters belong in the type instead of a runtime value.

use crypto_bigint::{const_monty_params, U2048};

const_monty_params!(
    Rfc5054_2048,
    U2048,
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
);

/// The 2048-bit RFC 5054 group, with its modulus in the type.
pub type Field2048 = crypto_bigint::modular::ConstMontyForm<Rfc5054_2048, { U2048::LIMBS }>;

#[cfg(feature = "wow-1-12-1")]
use crypto_bigint::U256;

/// The World of Warcraft 1.12.1 256-bit group.
#[cfg(feature = "wow-1-12-1")]
const_monty_params!(
    Wow1_12_1,
    U256,
    "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
);

/// The wow group, with its modulus in the type.
#[cfg(feature = "wow-1-12-1")]
pub type FieldWow = crypto_bigint::modular::ConstMontyForm<Wow1_12_1, { U256::LIMBS }>;

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "hash-sha1"))]
    use crypto_bigint::U2048;

    #[cfg(any(not(feature = "hash-sha1"), feature = "wow-1-12-1"))]
    fn golden_value(golden: &str, key: &str) -> Vec<u8> {
        let line = golden
            .lines()
            .find(|line| line.starts_with(key) && line[key.len()..].starts_with(" = "))
            .expect("the fixture has the value");
        let hex = line[key.len() + 3..].trim();

        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[cfg(not(feature = "hash-sha1"))]
    #[test]
    fn the_2048_bit_const_field_reproduces_the_verifier() {
        use super::Field2048;

        let golden = include_str!("../tests/golden/2048-sha512.txt");
        let x = golden_value(golden, "x");
        let v = golden_value(golden, "v");

        let mut x_padded = [0_u8; 256];
        x_padded[256 - x.len()..].copy_from_slice(&x);
        let exponent = U2048::from_be_slice(&x_padded);

        let generator = U2048::from_u8(2);
        let verifier = Field2048::new(&generator).pow(&exponent).retrieve();

        let bytes = verifier.to_be_bytes();
        assert_eq!(&bytes[bytes.len() - v.len()..], v.as_slice());
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn the_wow_const_field_reproduces_the_verifier() {
        use crypto_bigint::U256;

        use super::FieldWow;

        let golden = include_str!("../tests/golden/wow-sha1.txt");
        let x = golden_value(golden, "x");
        let v = golden_value(golden, "v");

        let mut x_padded = [0_u8; 32];
        x_padded[32 - x.len()..].copy_from_slice(&x);
        let exponent = U256::from_be_slice(&x_padded);

        let generator = U256::from_u8(7);
        let verifier = FieldWow::new(&generator).pow(&exponent).retrieve();

        let bytes = verifier.to_be_bytes();
        assert_eq!(&bytes[bytes.len() - v.len()..], v.as_slice());
    }
}
