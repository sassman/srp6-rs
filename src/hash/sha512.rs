pub use sha2::{digest::Update, Digest};

use crate::big_number::BigNumber;

pub const HASH_LENGTH: usize = 512 / 8;
pub type HashFunc = sha2::Sha512;

///
/// not yet verified
///
pub fn hash(a: &BigNumber, b: &BigNumber) -> BigNumber {
    HashFunc::new()
        .chain(a.to_array_pad_zero::<HASH_LENGTH>())
        .chain(b.to_array_pad_zero::<HASH_LENGTH>())
        .into()
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::*;

    #[test]
    #[allow(non_snake_case)]
    /// u = H(A, B)
    fn should_hash_2_big_numbers_with_sha256() {
        let A: BigNumber = "7BADE689AA63658C8DA684A78660BF1C62114269930D4141B9B30F75EDE466BB"
            .try_into()
            .unwrap();
        let B: BigNumber = "2CEC5E45B34CB20CABC099088CCF3D6B315F12DCBE070CC2F563D5447884D917"
            .try_into()
            .unwrap();

        let u = hash(&A, &B);
        let exp_hash: BigNumber =
            "B719062D3FAD531EF9BC1949629C349F405E201F0D285C6AA7D0AAE0FD709C00D0AE145A92BD18E376559844E914FB60F59AF2F1AC2BE894108B4FD8A9DFF5F9"
                .try_into()
                .unwrap();
        assert_eq!(&u, &exp_hash);
    }
}
