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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    /// the username is not one the WoW 1.12.1 client can send
    /// (see [`Username::new_wow`])
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

    /// Creates a new, validated [`Username`]. The text is kept as given: a
    /// flavour that folds case does so where it hashes, so the same name works
    /// with every group.
    ///
    /// # Errors
    /// Returns [`UsernameError`] if `s` is empty, contains a NUL byte, or
    /// contains a `:` (colon). See the type documentation for why the
    /// colon is rejected.
    pub fn new(s: impl Into<String>) -> std::result::Result<Self, UsernameError> {
        let s = s.into();
        Self::validate_common(&s)?;

        Ok(Self(s))
    }

    /// A [`Username`] the WoW 1.12.1 client can have sent: ASCII only, no
    /// control characters, 1 to 16 bytes, uppercased as that client sends it.
    ///
    /// The group folds the case itself when it hashes, so this is not needed for
    /// a handshake to verify; it refuses a name no such client can log in with.
    ///
    /// # Errors
    /// Returns [`UsernameError`] if `s` fails the common validation or is not
    /// 1 to 16 ASCII bytes without control characters.
    #[cfg(feature = "wow-1-12-1")]
    pub fn new_wow(s: impl Into<String>) -> std::result::Result<Self, UsernameError> {
        // The shared rules run first so an empty, NUL-bearing or colon-bearing
        // name reports the rule it broke: a NUL is also a control character.
        let name = Self::new(s)?;

        if name.len() > 16 || !name.is_ascii() || name.chars().any(|c| c.is_ascii_control()) {
            return Err(UsernameError::InvalidWowUsername);
        }

        Ok(Self(name.0.to_ascii_uppercase()))
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

#[cfg(test)]
mod username_tests {
    use super::*;

    #[test]
    fn should_expose_its_text_forms() {
        let username = Username::new("alice").unwrap();

        assert_eq!(&*username, "alice");
        assert_eq!(username.as_ref(), "alice");
        assert_eq!(username.to_string(), "alice");
    }

    /// The name is kept as given whichever features are on: folding it here
    /// would change what a group that hashes verbatim sees.
    #[test]
    fn should_keep_a_username_as_given() {
        assert_eq!(Username::new("Alice").unwrap().as_str(), "Alice");
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
        assert_eq!(Username::new_wow("alice").unwrap().as_str(), "ALICE");
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_report_the_common_rule_before_the_wow_one() {
        assert_eq!(
            Username::new_wow("ali\0ce").unwrap_err(),
            UsernameError::ContainsNulByte
        );
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_reject_a_too_long_username_for_wow() {
        assert_eq!(
            Username::new_wow("a_name_longer_than_16_bytes").unwrap_err(),
            UsernameError::InvalidWowUsername
        );
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn should_reject_non_ascii_for_wow() {
        assert_eq!(
            Username::new_wow("älice").unwrap_err(),
            UsernameError::InvalidWowUsername
        );
    }
}
