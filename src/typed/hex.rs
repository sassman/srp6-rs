use std::convert::TryFrom;

use std::fmt;

use crate::big_number::BigNumber;
use crate::{error::Srp6Error, Result};

pub(crate) fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02X}")?;
    }
    Ok(())
}

/// Creates a boundary value from the hex form its `Display` prints.
pub trait FromHexString: Sized {
    /// Decodes `hex`; ASCII whitespace between the digits is ignored.
    fn try_from_hex(hex: &str) -> Result<Self>;
}

/// Decodes base-16 into bytes, preserving leading zero bytes. ASCII
/// whitespace, including `\n` and `\r`, is stripped first.
pub(crate) fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let compact: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();

    // Reject non-ASCII before slicing: byte indexing into a multibyte char
    // would panic instead of reporting bad hex.
    if !compact.is_ascii() || !compact.len().is_multiple_of(2) {
        return Err(Srp6Error::InvalidHexString);
    }

    let mut bytes = Vec::with_capacity(compact.len() / 2);
    for i in (0..compact.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&compact[i..i + 2], 16).map_err(|_| Srp6Error::InvalidHexString)?;
        bytes.push(byte);
    }

    Ok(bytes)
}

impl FromHexString for BigNumber {
    fn try_from_hex(hex: &str) -> Result<Self> {
        BigNumber::try_from(hex).map_err(|_| Srp6Error::InvalidHexString)
    }
}
