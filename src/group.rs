//! Const Montgomery parameters for the closed SRP groups.
//!
//! RFC 5054 appendix A and the 1.12.1 wow group each fix one modulus, so their
//! Montgomery parameters belong in the type instead of a runtime value.
//!
//! [`Group`] is the public marker: a caller picks one of the closed groups and
//! never sees the field arithmetic. That lives in the doc-hidden [`GroupOps`],
//! so the backend types stay out of the documented API.

use crypto_bigint::{
    const_monty_params, U1024, U1088, U1536, U1600, U2048, U2112, U3072, U3136, U4096, U4160,
    U6144, U6208, U8192, U8320,
};
use rand::{rng, RngExt};

use crate::big_number::BigNumber;
use crate::hash::{Digest, HashFunc, Update};

#[cfg(feature = "wow-1-12-1")]
use crypto_bigint::{U256, U384};

const N1024: &str = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3";
const N1536: &str = "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB";
const N2048: &str = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
const N3072: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
const N4096: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";
const N6144: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF";
const N8192: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF";
#[cfg(feature = "wow-1-12-1")]
const NWOW: &str = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7";

const_monty_params!(Rfc5054_1024, U1024, N1024);
pub(crate) type Field1024 = crypto_bigint::modular::ConstMontyForm<Rfc5054_1024, { U1024::LIMBS }>;

const_monty_params!(Rfc5054_1536, U1536, N1536);
pub(crate) type Field1536 = crypto_bigint::modular::ConstMontyForm<Rfc5054_1536, { U1536::LIMBS }>;

const_monty_params!(Rfc5054_2048, U2048, N2048);
pub(crate) type Field2048 = crypto_bigint::modular::ConstMontyForm<Rfc5054_2048, { U2048::LIMBS }>;

const_monty_params!(Rfc5054_3072, U3072, N3072);
pub(crate) type Field3072 = crypto_bigint::modular::ConstMontyForm<Rfc5054_3072, { U3072::LIMBS }>;

const_monty_params!(Rfc5054_4096, U4096, N4096);
pub(crate) type Field4096 = crypto_bigint::modular::ConstMontyForm<Rfc5054_4096, { U4096::LIMBS }>;

const_monty_params!(Rfc5054_6144, U6144, N6144);
pub(crate) type Field6144 = crypto_bigint::modular::ConstMontyForm<Rfc5054_6144, { U6144::LIMBS }>;

const_monty_params!(Rfc5054_8192, U8192, N8192);
pub(crate) type Field8192 = crypto_bigint::modular::ConstMontyForm<Rfc5054_8192, { U8192::LIMBS }>;

#[cfg(feature = "wow-1-12-1")]
const_monty_params!(Wow1_12_1, U256, NWOW);

#[cfg(feature = "wow-1-12-1")]
pub(crate) type FieldWow = crypto_bigint::modular::ConstMontyForm<Wow1_12_1, { U256::LIMBS }>;

mod sealed {
    pub trait Sealed {}
}

/// A closed SRP group.
///
/// The set is closed: [`Group1024`] to [`Group8192`] are the RFC 5054 appendix A
/// groups and, behind `wow-1-12-1`, `GroupWow` is the 1.12.1 client's. Pick one
/// through [`crate::Srp6`]; the trait only names the sizes and the encodings the
/// handshake needs.
pub trait Group: Default + sealed::Sealed {
    /// The modulus width in bytes.
    const N_BYTES: usize;
    /// The salt width in bytes.
    const SALT_BYTES: usize;

    /// The modulus `N`, big-endian.
    fn modulus_bytes(&self) -> Vec<u8>;
    /// The generator `g`, big-endian, `N_BYTES` wide.
    fn generator_bytes(&self) -> Vec<u8>;
    /// The multiplier `k`, big-endian, `N_BYTES` wide.
    fn multiplier_bytes(&self) -> Vec<u8>;
}

/// The typed arithmetic behind [`Group`].
///
/// Hidden and sealed: callers pick a group and use [`crate::Srp6`]'s methods,
/// so the crypto-bigint field types never reach the documented API.
#[doc(hidden)]
pub trait GroupOps: Group {
    type Field: Clone;
    type Exponent: Clone;

    fn generator(&self) -> Self::Field;
    fn multiplier(&self) -> Self::Field;

    /// Decodes a big-endian value, refusing one that is 0 modulo N.
    fn field_from_bytes(&self, bytes: &[u8]) -> Option<Self::Field>;
    /// Fixed-width big-endian encoding, `N_BYTES` long.
    fn field_to_bytes(&self, value: &Self::Field) -> Vec<u8>;
    fn field_add(&self, a: &Self::Field, b: &Self::Field) -> Self::Field;
    fn field_sub(&self, a: &Self::Field, b: &Self::Field) -> Self::Field;
    fn field_mul(&self, a: &Self::Field, b: &Self::Field) -> Self::Field;
    fn field_pow(&self, base: &Self::Field, exp: &Self::Exponent) -> Self::Field;

    fn random_exponent(&self) -> Self::Exponent;
    fn exponent_from_hash(&self, hash: &BigNumber) -> Self::Exponent;
    fn exponent_add(&self, a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent;
    fn exponent_mul(&self, a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent;
}

macro_rules! closed_group {
    ($name:ident, $field:ident, $uint:ident, $exp:ident, $hex:ident, $g:expr, $n_bytes:expr, $salt_bytes:expr, $k:expr) => {
        #[derive(Default)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Group for $name {
            const N_BYTES: usize = $n_bytes;
            const SALT_BYTES: usize = $salt_bytes;

            fn modulus_bytes(&self) -> Vec<u8> {
                <$uint>::from_be_hex($hex).to_be_bytes().to_vec()
            }

            fn generator_bytes(&self) -> Vec<u8> {
                let mut bytes = vec![0_u8; $n_bytes];
                bytes[$n_bytes - 1] = $g;
                bytes
            }

            fn multiplier_bytes(&self) -> Vec<u8> {
                match $k {
                    Some(k) => {
                        let mut bytes = vec![0_u8; $n_bytes];
                        bytes[$n_bytes - 1] = k;
                        bytes
                    }
                    None => {
                        let hash = HashFunc::new()
                            .chain(&self.modulus_bytes())
                            .chain(&self.generator_bytes())
                            .finalize();
                        let mut bytes = vec![0_u8; $n_bytes];
                        bytes[$n_bytes - hash.len()..].copy_from_slice(&hash);
                        bytes
                    }
                }
            }
        }

        impl GroupOps for $name {
            type Field = $field;
            type Exponent = $exp;

            fn generator(&self) -> Self::Field {
                $field::new(&<$uint>::from_u8($g))
            }

            fn multiplier(&self) -> Self::Field {
                self.field_from_bytes(&self.multiplier_bytes())
                    .expect("the multiplier is not 0 mod N")
            }

            fn field_from_bytes(&self, bytes: &[u8]) -> Option<Self::Field> {
                if bytes.len() > $n_bytes {
                    return None;
                }
                let mut padded = vec![0_u8; $n_bytes];
                padded[$n_bytes - bytes.len()..].copy_from_slice(bytes);
                let field = $field::new(&<$uint>::from_be_slice(&padded));
                if field.retrieve().is_zero().to_bool() {
                    None
                } else {
                    Some(field)
                }
            }

            fn field_to_bytes(&self, value: &Self::Field) -> Vec<u8> {
                value.retrieve().to_be_bytes().to_vec()
            }

            fn field_add(&self, a: &Self::Field, b: &Self::Field) -> Self::Field {
                a + b
            }

            fn field_sub(&self, a: &Self::Field, b: &Self::Field) -> Self::Field {
                a - b
            }

            fn field_mul(&self, a: &Self::Field, b: &Self::Field) -> Self::Field {
                a * b
            }

            fn field_pow(&self, base: &Self::Field, exp: &Self::Exponent) -> Self::Field {
                base.pow(exp)
            }

            fn random_exponent(&self) -> Self::Exponent {
                let bytes: Vec<u8> = rng()
                    .random_iter()
                    .take(<$exp>::BITS as usize / 8)
                    .collect();
                <$exp>::from_be_slice(&bytes)
            }

            fn exponent_from_hash(&self, hash: &BigNumber) -> Self::Exponent {
                let raw = hash.to_vec();
                let width = <$exp>::BITS as usize / 8;
                let mut padded = vec![0_u8; width];
                if raw.len() > width {
                    padded.copy_from_slice(&raw[raw.len() - width..]);
                } else {
                    padded[width - raw.len()..].copy_from_slice(&raw);
                }
                <$exp>::from_be_slice(&padded)
            }

            fn exponent_add(&self, a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
                *a + *b
            }

            fn exponent_mul(&self, a: &Self::Exponent, b: &Self::Exponent) -> Self::Exponent {
                *a * *b
            }
        }
    };
}

closed_group!(Group1024, Field1024, U1024, U1088, N1024, 2, 128, 128, None);
closed_group!(Group1536, Field1536, U1536, U1600, N1536, 2, 192, 192, None);
closed_group!(Group2048, Field2048, U2048, U2112, N2048, 2, 256, 256, None);
closed_group!(Group3072, Field3072, U3072, U3136, N3072, 5, 384, 384, None);
closed_group!(Group4096, Field4096, U4096, U4160, N4096, 5, 512, 512, None);
closed_group!(Group6144, Field6144, U6144, U6208, N6144, 5, 768, 768, None);
closed_group!(Group8192, Field8192, U8192, U8320, N8192, 19, 1024, 1024, None);

#[cfg(feature = "wow-1-12-1")]
closed_group!(GroupWow, FieldWow, U256, U384, NWOW, 7, 32, 32, Some(3));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Username;
    use crate::primitives::*;

    /// The const field must reproduce the dynamic verifier for the same x.
    macro_rules! const_group_matches_dynamic {
        ($name:ident, $field:ident, $uint:ident, $g:expr, $group:ident) => {
            #[test]
            fn $name() {
                let group = $group;
                let n = PrimeModulus::from_bytes_be(&group.modulus_bytes());
                let g = Generator::from_bytes_be(&group.generator_bytes());
                let salt =
                    Salt::from_hex_str_be("BEB25379D1A8581EB5A727673A2441EE").expect("valid hex");
                let username = Username::new("alice").expect("valid username");
                let x = calculate_private_key_x(&username, "password123", &salt);

                let n_bytes = (<$uint>::BITS / 8) as usize;
                let x_bytes = x.to_vec();
                assert!(x_bytes.len() <= n_bytes);
                let mut padded = vec![0_u8; n_bytes];
                padded[n_bytes - x_bytes.len()..].copy_from_slice(&x_bytes);
                let exponent = <$uint>::from_be_slice(&padded);

                let generator = <$uint>::from_u8($g);
                let verifier = $field::new(&generator).pow(&exponent).retrieve();

                let expected = calculate_password_verifier_v(&n, &g, &x).to_vec();
                let actual = verifier.to_be_bytes();
                assert_eq!(
                    &actual[actual.len() - expected.len()..],
                    expected.as_slice()
                );
            }
        };
    }

    const_group_matches_dynamic!(const_1024_matches_dynamic, Field1024, U1024, 2, Group1024);
    const_group_matches_dynamic!(const_1536_matches_dynamic, Field1536, U1536, 2, Group1536);
    const_group_matches_dynamic!(const_2048_matches_dynamic, Field2048, U2048, 2, Group2048);
    const_group_matches_dynamic!(const_3072_matches_dynamic, Field3072, U3072, 5, Group3072);
    const_group_matches_dynamic!(const_4096_matches_dynamic, Field4096, U4096, 5, Group4096);
    const_group_matches_dynamic!(const_6144_matches_dynamic, Field6144, U6144, 5, Group6144);
    const_group_matches_dynamic!(const_8192_matches_dynamic, Field8192, U8192, 19, Group8192);

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
