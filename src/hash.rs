use crate::big_number::BigNumber;
pub use sha1::Digest;

pub const HASH_LENGTH: usize = 20;
pub type Hash = [u8; HASH_LENGTH];
pub type HashFunc = sha1::Sha1;

///
/// not yet verified
///
pub fn hash<const KEY_BYTES: usize>(a: &BigNumber, b: &BigNumber) -> BigNumber {
    HashFunc::new()
        .chain(a.to_array_pad_zero::<KEY_BYTES>())
        .chain(b.to_array_pad_zero::<KEY_BYTES>())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    #[allow(non_snake_case)]
    /// u = H(A, B)
    fn should_hash_2_big_numbers() {
        let A: BigNumber = "7BADE689AA63658C8DA684A78660BF1C62114269930D4141B9B30F75EDE466BB"
            .try_into()
            .unwrap();
        let B: BigNumber = "2CEC5E45B34CB20CABC099088CCF3D6B315F12DCBE070CC2F563D5447884D917"
            .try_into()
            .unwrap();

        let u = hash::<32>(&A, &B);
        let exp_hash: BigNumber = "DBC0E8AE033ACA9A9066E583DC160CB741A39737"
            .try_into()
            .unwrap();
        assert_eq!(&u, &exp_hash);
    }
}
