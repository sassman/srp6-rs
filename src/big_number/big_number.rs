use crate::hash::*;

use crypto_bigint::BoxedUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

use super::crypto::Inner;

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
pub(crate) struct BigNumber(Inner);

#[derive(Error, Debug)]
pub(crate) enum BigNumberError {
    #[error("Invalid hex string.")]
    InvalidHexStr,
}

/// new empty unsigned big number
impl Default for BigNumber {
    fn default() -> Self {
        Self(Inner::zero())
    }
}

impl BigNumber {
    /// `raw` is expected to be big endian
    pub fn from_bytes_be(raw: &[u8]) -> Self {
        Self(Inner::from_bytes_be(raw))
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

    pub fn num_bytes(&self) -> usize {
        self.0.num_bytes()
    }

    /// The magnitude, for the runtime-modulus math in `primitives`.
    pub(crate) fn as_boxed_uint(&self) -> &BoxedUint {
        self.0.as_boxed_uint()
    }

    /// returns the byte vec in little endian byte order
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// the counter part of `::to_vec()`
    pub fn from_vec(data: &[u8]) -> Self {
        Self::from_bytes_be(data)
    }

    /// The runtime-length form of [`BigNumber::to_array_pad_zero`].
    pub(crate) fn to_array_pad_zero_len(&self, len: usize) -> Vec<u8> {
        let pad = self.num_bytes().max(len);

        let unpadded = self.to_vec();
        let mut padded = vec![0; pad];
        padded[pad - unpadded.len()..].copy_from_slice(&unpadded);

        padded
    }
}

/// Constant-time equality for values of the same width.
///
/// Crate-private on purpose: the verification path needs the guarantee, but
/// the trait is not part of the public API.
pub(crate) trait ConstantTimeEq {
    fn ct_eq(&self, other: &Self) -> bool;
}

impl ConstantTimeEq for BigNumber {
    fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

#[test]
fn constant_time_equality_matches_value_equality() {
    let seven = BigNumber::from(7);
    assert!(seven.ct_eq(&BigNumber::from(7)));
    assert!(!seven.ct_eq(&BigNumber::from(8)));
    assert!(BigNumber::default().ct_eq(&BigNumber::from(0)));
}

impl Debug for BigNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "BigNumber(\"{}\")", self)
    }
}

// region from traits
impl From<u32> for BigNumber {
    fn from(n: u32) -> Self {
        Self(Inner::from_u32(n))
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
        let hex = x.0.to_hex();

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
fn should_pad_0() {
    let x = BigNumber::from_bytes_be(&[0x11, 0xcd]);
    assert_eq!(x.to_array_pad_zero_len(3), [0, 0x11, 0xcd]);

    assert_eq!(x.to_array_pad_zero_len(1), [0x11, 0xcd]);
}

#[test]
fn should_should_work_with_odd_byte_count() {
    assert_eq!(BigNumber::from_hex_str_be("6").unwrap().to_string(), "6");
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

#[test]
fn test_network_endianess() {
    assert_eq!(
        hex_literal::hex!("AB 11 CD"),
        [0xAB, 0x11, 0xCD],
        "we trust the hex_literal crate"
    );
    let b = BigNumber::try_from("AB 11 CD").unwrap();
    assert_eq!(b.to_array_pad_zero_len(3), [0xAB, 0x11, 0xCD]);
    assert_eq!(b.to_vec(), [0xAB, 0x11, 0xCD]);
    assert_eq!(b.to_string(), "AB11CD");
}
