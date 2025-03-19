pub use sha1::{digest::Update, Digest};

use crate::big_number::BigNumber;

pub const HASH_LENGTH: usize = 20;
pub type HashFunc = sha1::Sha1;

/// sha1 hash function
/// Caution: sha1 is cryptographically broken and should not be used for secure applications
pub fn hash_w_pad<const PAD: usize>(a: &BigNumber, b: &BigNumber) -> BigNumber {
    BigNumber::from_bytes_be(
        HashFunc::new()
            .chain(a.to_array_pad_zero::<PAD>())
            .chain(b.to_array_pad_zero::<PAD>())
            .finalize()
            .as_slice(),
    )
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use std::convert::TryFrom;

    use super::*;
    use crate::prelude::PublicKey;

    #[test]
    #[allow(non_snake_case)]
    /// u = H(A, B)
    fn should_hash_2_big_numbers_with_sha1() {
        let A = PublicKey::try_from(
            "61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
             4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
             8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
             BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
             B349EF5D 76988A36 72FAC47B 0769447B",
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

        // 128 bytes from the 1024 bit N section of appendix A
        let u = hash_w_pad::<128>(&A, &B);
        let exp_hash = hex!("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019");

        assert_eq!(u.to_vec(), exp_hash);
    }
}
