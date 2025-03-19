use crate::hash::*;

use num_bigint::{BigInt, Sign};
use rand::{rng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

/// also exporting the trait here
pub use num_traits::Zero;
pub use std::ops::{Add, Mul, Rem, Sub};

impl Serialize for BigNumber {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.to_vec().as_slice())
    }
}

impl<'de> Deserialize<'de> for BigNumber {
    fn deserialize<D>(deserializer: D) -> std::result::Result<BigNumber, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self::from_vec(&bytes))
    }
}

/// [`BigNumber`] helps to work with big numbers as in openssl used.
#[derive(PartialEq, Clone)]
pub struct BigNumber(BigInt);

#[derive(Error, Debug)]
pub enum BigNumberError {
    #[error("Invalid hex string.")]
    InvalidHexStr,
}

/// new empty unsigned big number
impl Default for BigNumber {
    fn default() -> Self {
        Self(BigInt::new(Sign::Plus, vec![]))
    }
}

impl BigNumber {
    /// new random initialized big number
    pub fn new_rand(n_bytes: usize) -> Self {
        let rng = rng();
        let bytes: Vec<u8> = rng.random_iter().take(n_bytes).collect();
        Self(BigInt::from_bytes_be(Sign::Plus, &bytes))
    }

    /// `raw` is expected to be big endian
    pub fn from_bytes_be(raw: &[u8]) -> Self {
        Self(BigInt::from_bytes_be(Sign::Plus, raw))
    }

    /// `raw` is expected to be big endian
    pub fn from_bytes_le(raw: &[u8]) -> Self {
        Self(BigInt::from_bytes_le(Sign::Plus, raw))
    }

    /// from hex string, hex strings are always big endian:
    /// High
    ///    -> Low
    ///  "123acab"
    /// This method strips all non alphanumerical, So block formats are also supported.
    pub fn from_hex_str_be(str: &str) -> std::result::Result<Self, BigNumberError> {
        let str = str
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();

        let str = if str.len() % 2 != 0 {
            format!("{:0>len$}", str, len = (str.len() / 2 + 1) * 2)
        } else {
            str.to_owned()
        };

        let mut bytes_be = Vec::with_capacity(str.len() / 2);

        for i in (0..str.len()).step_by(2) {
            let byte_str = &str[i..i + 2];
            let byte =
                u8::from_str_radix(byte_str, 16).map_err(|_| BigNumberError::InvalidHexStr)?;
            bytes_be.push(byte);
        }

        Ok(Self::from_bytes_be(&bytes_be))
    }

    pub fn modpow(&self, exponent: &Self, modulo: &Self) -> Self {
        self.0.modpow(&exponent.0, &modulo.0).into()
    }

    pub fn num_bytes(&self) -> usize {
        (self.0.bits() as usize + 7) / 8
    }

    /// returns the byte vec in little endian byte order
    pub fn to_vec(&self) -> Vec<u8> {
        let (_, x) = self.0.to_bytes_be();
        x
    }

    /// the counter part of `::to_vec()`
    pub fn from_vec(data: &[u8]) -> Self {
        Self::from_bytes_be(data)
    }

    /// returns the byte vec in little endian byte order, padded by 0 for `len` bytes
    pub fn to_array_pad_zero<const N: usize>(&self) -> Vec<u8> {
        let pad = self.num_bytes().max(N);

        let unpadded = self.to_vec();
        let mut padded = vec![0; pad];
        padded[pad - unpadded.len()..].copy_from_slice(&unpadded);

        padded
    }
}

#[test]
fn test_mod_exp() {
    let a = BigNumber::from_hex_str_be("6").unwrap();
    let p = BigNumber::from_hex_str_be("3").unwrap();
    let m = BigNumber::from_hex_str_be("7").unwrap();
    let r = a.modpow(&p, &m);

    assert_eq!(&r, &BigNumber::from(6), "{} is not 6", &r);
    assert_eq!(
        &a.modpow(&p, &m),
        &BigNumber::from(6),
        "{}.modExp(3, 7) is not 6",
        &r
    );
}

impl Debug for BigNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "BigNumber(\"{}\")", self)
    }
}

// region from traits
impl From<u32> for BigNumber {
    fn from(n: u32) -> Self {
        Self(BigInt::from(n))
    }
}

impl From<BigInt> for BigNumber {
    fn from(a: BigInt) -> Self {
        Self(a)
    }
}

impl<const N: usize> From<[u8; N]> for BigNumber {
    fn from(k: [u8; N]) -> Self {
        Self::from_bytes_be(&k)
    }
}

impl From<HashFunc> for BigNumber {
    fn from(hasher: HashFunc) -> Self {
        hasher.finalize().as_slice().into()
    }
}

impl From<&[u8]> for BigNumber {
    fn from(somewhere: &[u8]) -> Self {
        Self::from_bytes_be(somewhere)
    }
}

impl From<&BigNumber> for String {
    /// Returns a hex string representation of the big number
    /// it is formatted in 8 hex chars per block (hexlets)
    /// and 7 hexlets per line
    fn from(x: &BigNumber) -> Self {
        let hex = x.0.to_str_radix(16).to_uppercase();

        let hexlets: Vec<String> = hex
            .chars()
            .collect::<Vec<_>>()
            .chunks(8)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect();

        // Group 7 hexlets per line
        hexlets
            .chunks(7)
            .map(|line| line.join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl From<BigNumber> for String {
    fn from(x: BigNumber) -> Self {
        (&x).into()
    }
}

impl TryFrom<&str> for BigNumber {
    type Error = BigNumberError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_hex_str_be(value)
    }
}

impl TryFrom<String> for BigNumber {
    type Error = BigNumberError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex_str_be(value.as_str())
    }
}

#[test]
fn should_try_from_string() {
    use std::convert::TryInto;

    let s = "ab11cd".to_string();
    let x: BigNumber = s.try_into().unwrap();
    assert_eq!(x.to_vec(), &[0xab, 0x11, 0xcd]);
}

#[test]
fn should_from_bytes() {
    let x = BigNumber::from_bytes_be(&[0xab, 0x11, 0xcd]);
    assert_eq!(x.to_vec(), &[0xab, 0x11, 0xcd]);
}

#[test]
fn should_to_vec() {
    let x = BigNumber::from_hex_str_be("ab11cd").unwrap();
    assert_eq!(x.to_vec(), &[0xab, 0x11, 0xcd]);
}

#[test]
fn should_random_initialize() {
    let x = BigNumber::new_rand(10);
    assert_ne!(x, BigNumber::default());
}

#[test]
fn should_pad_0() {
    let x = BigNumber::from_bytes_be(&[0x11, 0xcd]);
    assert_eq!(x.to_array_pad_zero::<3>(), [0, 0x11, 0xcd]);

    assert_eq!(x.to_array_pad_zero::<1>(), [0x11, 0xcd]);
}

#[test]
fn should_should_work_with_odd_byte_count() {
    assert_eq!(BigNumber::from_hex_str_be("6").unwrap().to_string(), "6");
}
// endregion

// region modulo
impl Rem for &BigNumber {
    type Output = BigNumber;

    fn rem(self, rhs: &BigNumber) -> Self::Output {
        (&self.0).rem(&rhs.0).into()
    }
}
#[test]
fn should_modulo_ref() {
    let a = &BigNumber::from(10);
    assert_eq!(a.rem(&BigNumber::from(4)), BigNumber::from(10 % 4));
}
impl Rem for BigNumber {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        (&self).rem(&rhs)
    }
}
#[test]
fn should_modulo() {
    let exp = BigNumber::from(7 % 6);
    assert_eq!(BigNumber::from(7) % BigNumber::from(6), exp);
}
// endregion

// region mul, add, sub
impl Mul for BigNumber {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        (self.0 * rhs.0).into()
    }
}

impl Mul for &BigNumber {
    type Output = BigNumber;

    fn mul(self, rhs: Self) -> Self::Output {
        (&self.0 * &rhs.0).into()
    }
}

#[test]
fn test_big_num_mul() {
    let a = BigNumber::from(4);
    let b = BigNumber::from(2);
    let exp = BigNumber::from(8);
    assert_eq!(a * b, exp);
}

impl Add for BigNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.0.add(rhs.0).into()
    }
}
impl<'b> Add<&'b BigNumber> for &BigNumber {
    type Output = BigNumber;

    fn add(self, rhs: &'b BigNumber) -> Self::Output {
        (&self.0).add(&rhs.0).into()
    }
}

impl Sub for BigNumber {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0.sub(rhs.0).into()
    }
}
#[test]
fn should_subtract() {
    let (a, b) = (BigNumber::from(6), BigNumber::from(1));
    assert_eq!(a - b, BigNumber::from(5));
}

impl<'b> Sub<&'b BigNumber> for &BigNumber {
    type Output = BigNumber;

    fn sub(self, rhs: &'b BigNumber) -> Self::Output {
        (&self.0).sub(&rhs.0).into()
    }
}
#[test]
fn should_subtract_refs() {
    let (a, b) = (BigNumber::from(6), BigNumber::from(6));
    assert_eq!(&a - &b, BigNumber::from(0));
}
// endregion

impl Display for BigNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let x: String = self.into();
        write!(f, "{}", x)
    }
}

#[test]
fn test_whitespace_is_ignored() {
    assert_eq!(
        BigNumber::try_from("A B 1 1 C D",).unwrap(),
        BigNumber::from_hex_str_be("AB11CD",).unwrap()
    );
}

#[test]
fn test_into_string_and_display() {
    let expected = "3E9D557B 7899AC2A 8DEC8D00 46FB310A 42A233BD 1DF0244B 574AB946\nA22A4A18";
    let x = BigNumber::from_hex_str_be(
        "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18",
    )
    .unwrap();
    let s: String = x.into();
    assert_eq!(s, expected);
    assert_eq!(
        format!(
            "{}",
            BigNumber::from_hex_str_be(
                "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18",
            )
            .unwrap()
        ),
        expected
    );
}

#[test]
fn test_serde_behaviour() {
    let v = "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18";
    let b = BigNumber::from_hex_str_be(v).unwrap();

    let b_str = serde_json::to_string(&b).unwrap();
    let b2 = serde_json::from_str::<BigNumber>(&b_str).unwrap();
    assert_eq!(b, b2);
}

impl Zero for BigNumber {
    fn zero() -> Self {
        BigInt::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

#[test]
fn test_network_endianess() {
    assert_eq!(
        hex_literal::hex!("AB 11 CD"),
        [0xAB, 0x11, 0xCD],
        "we trust the hex_literal crate"
    );
    assert_eq!(
        BigInt::from_bytes_be(Sign::Plus, &[0xAB, 0x11, 0xCD]),
        BigInt::parse_bytes(b"AB11CD", 16).unwrap(),
        "BigInt::from_bytes_be is big endian"
    );
    let b = BigNumber::try_from("AB 11 CD").unwrap();
    assert_eq!(b.to_array_pad_zero::<3>(), [0xAB, 0x11, 0xCD]);
    assert_eq!(b.to_vec(), [0xAB, 0x11, 0xCD]);
    assert_eq!(b.to_string(), "AB11CD");
}
