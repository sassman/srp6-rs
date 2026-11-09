//! The credential types a caller supplies: the username `I` and the
//! cleartext password `p`. They sit at the boundary, not in the field calculus.

mod username;

pub use username::{Username, UsernameError, UsernameRef};

/// Clear text password `p` as [`str`]
#[doc(alias("P", "p"))]
pub type ClearTextPassword = String;
pub type ClearTextPasswordRef<'a> = &'a str;
