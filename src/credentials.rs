//! The credential types a caller supplies: the username `I` and the
//! cleartext password `p`. They sit at the boundary, not in the field calculus.

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use thiserror::Error;

/// Username `I`, validated so it can never contain the `:` separator
/// used by the private key derivation, a NUL byte, or be empty.
///
/// The colon rule matters because the private key derivation formula
/// `x = H(s | H(I ":" p))` joins the username and password with a
/// literal colon. If `I` itself could contain a colon, the pre-image
/// would become ambiguous: `("a:b", "c")` and `("a", "b:c")` would hash
/// to exactly the same value.
#[doc(alias = "I")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Username(String);
/// Reference to a validated [`Username`] `I`
pub type UsernameRef<'a> = &'a Username;

/// Errors returned by [`Username::new`]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum UsernameError {
    /// the username was empty
    #[error("username must not be empty")]
    Empty,

    /// the username contained a NUL byte
    #[error("username must not contain a NUL byte")]
    ContainsNulByte,

    /// the username contained a `:` (colon)
    ///
    /// `x = H(s | H(I ":" p))` joins the username and password with a
    /// literal colon, so a colon inside the username would make the
    /// pre-image ambiguous, e.g. `("a:b", "c")` and `("a", "b:c")` would
    /// hash identically.
    #[error(
        "username must not contain a ':' (colon): it is the separator in `H(I \":\" p)`, so \
         a colon inside the username would make the pre-image ambiguous, e.g. (\"a:b\", \"c\") \
         and (\"a\", \"b:c\") would hash identically"
    )]
    ContainsColon,

    /// the username did not satisfy the WoW 1.12.1 client's normalisation
    /// (see [`Username::new`] under the `wow-1-12-1` feature)
    #[cfg(feature = "wow-1-12-1")]
    #[error(
        "username must be 1 to 16 ASCII bytes without control characters (WoW client limitation)"
    )]
    InvalidWowUsername,
}

impl Username {
    /// The rules that hold for every flavour: non-empty, no NUL byte, no `:`.
    /// See the type documentation for why the colon is rejected.
    fn validate_common(s: &str) -> std::result::Result<(), UsernameError> {
        if s.is_empty() {
            return Err(UsernameError::Empty);
        }
        if s.contains('\0') {
            return Err(UsernameError::ContainsNulByte);
        }
        if s.contains(':') {
            return Err(UsernameError::ContainsColon);
        }

        Ok(())
    }

    /// Creates a new, validated [`Username`]
    ///
    /// # Errors
    /// Returns [`UsernameError`] if `s` is empty, contains a NUL byte, or
    /// contains a `:` (colon). See the type documentation for why the
    /// colon is rejected.
    #[cfg(not(feature = "wow-1-12-1"))]
    pub fn new(s: impl Into<String>) -> std::result::Result<Self, UsernameError> {
        let s = s.into();
        Self::validate_common(&s)?;

        Ok(Self(s))
    }

    /// Creates a new [`Username`] normalised the way the WoW 1.12.1 client
    /// does it: ASCII only, no control characters, 1 to 16 bytes, uppercased.
    ///
    /// This shadows the general constructor rather than sitting beside it as a
    /// second one, because a build talks to exactly one flavour of peer. With
    /// two constructors every call site would need its own `#[cfg]` to pick,
    /// and the paths that cannot take one - `TryFrom<String>`, and through it
    /// `Deserialize` - would silently keep the unnormalised form, so the same
    /// build could produce two different `Username`s for one input.
    ///
    /// # Errors
    /// Returns [`UsernameError`] if `s` is not 1 to 16 ASCII bytes without
    /// control characters, or fails the common validation (e.g. contains a
    /// colon).
    #[cfg(feature = "wow-1-12-1")]
    pub fn new(s: impl Into<String>) -> std::result::Result<Self, UsernameError> {
        let s = s.into();
        // The shared rules run first so that an empty, NUL-bearing or
        // colon-bearing name reports the rule it actually broke, the same way it
        // does without this feature. Checking the WoW envelope first would
        // report `InvalidWowUsername` for all three, since a NUL is also an
        // ASCII control character.
        Self::validate_common(&s)?;

        if s.len() > 16 || !s.is_ascii() || s.chars().any(|c| c.is_ascii_control()) {
            return Err(UsernameError::InvalidWowUsername);
        }

        // Re-validating after uppercasing would be redundant: `s` is ASCII, so
        // `to_uppercase` only maps a-z to A-Z and cannot introduce a NUL, a
        // colon, or emptiness.
        Ok(Self(s.to_uppercase()))
    }

    /// borrows the username as [`&str`]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Username {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<String> for Username {
    type Error = UsernameError;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::new(s)
    }
}

/// Clear text password `p` as [`str`]
#[doc(alias("P", "p"))]
pub type ClearTextPassword = String;
pub type ClearTextPasswordRef<'a> = &'a str;

#[cfg(test)]
mod username_tests {
    use super::*;

    /// The WoW flavour uppercases, so it asserts its own form in
    /// `should_uppercase_for_wow` below.
    #[cfg(not(feature = "wow-1-12-1"))]
    #[test]
    fn should_accept_a_normal_username() {
        assert_eq!(Username::new("alice").unwrap().as_str(), "alice");
    }

    #[test]
    fn should_reject_an_empty_username() {
        assert_eq!(Username::new("").unwrap_err(), UsernameError::Empty);
    }

    #[test]
    fn should_reject_a_nul_byte() {
        assert_eq!(
            Username::new("ali\0ce").unwrap_err(),
            UsernameError::ContainsNulByte
        );
    }

    #[test]
    fn should_reject_a_colon() {
        assert_eq!(
            Username::new("ali:ce").unwrap_err(),
            UsernameError::ContainsColon
        );
    }

    /// Flavour-agnostic: the wire form is the username's own normalised form,
    /// whichever flavour is compiled in.
    #[test]
    fn should_round_trip_through_serde_json() {
        let username = Username::new("alice").unwrap();
        let json = serde_json::to_string(&username).unwrap();
        assert_eq!(json, format!("\"{}\"", username.as_str()));
        assert_eq!(serde_json::from_str::<Username>(&json).unwrap(), username);
    }

    #[test]
    fn should_reject_an_invalid_username_on_deserialize() {
        let err = serde_json::from_str::<Username>("\"ali:ce\"").unwrap_err();
        assert!(err.to_string().contains("colon"));
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_uppercase_for_wow() {
        assert_eq!(Username::new("alice").unwrap().as_str(), "ALICE");
    }

    /// Why `new` is shadowed instead of paired with a separate `new_wow`:
    /// `Deserialize` reaches the constructor through `TryFrom<String>`, so it
    /// has to pick up the flavour's normalisation too. With a second
    /// constructor this path kept the unnormalised form and yielded "alice",
    /// disagreeing with a directly constructed `Username` in the same build.
    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_uppercase_on_deserialize_for_wow() {
        let deserialized: Username = serde_json::from_str("\"alice\"").unwrap();
        assert_eq!(deserialized.as_str(), "ALICE");
        assert_eq!(deserialized, Username::new("alice").unwrap());
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_reject_a_too_long_username_for_wow() {
        assert_eq!(
            Username::new("a_name_longer_than_16_bytes").unwrap_err(),
            UsernameError::InvalidWowUsername
        );
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_reject_non_ascii_for_wow() {
        assert_eq!(
            Username::new("älice").unwrap_err(),
            UsernameError::InvalidWowUsername
        );
    }
}
