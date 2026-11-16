/*!
The World of Warcraft 1.12.1 (build 5875) group.

Behind the `wow-1-12-1` feature. The rest of that client's flavour belongs to
this group and to no other: `k = 3`, and a username and password uppercased
where they are hashed, so a caller may hold them in any case.
[`crate::Username::new_wow`] refuses a name that client cannot send.

This group is not safe for anything else. `N` is 256 bit, far below the
[RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
groups in [`crate::rfc_5054_appendix_a`], and the flavour hashes with SHA-1.
It exists to talk to a client that shipped in 2006.
*/

pub use crate::group::GroupWow;

/// The 1.12.1 client's handshake: `g = 7` and a 256-bit `N`, as
/// `CMD_AUTH_LOGON_CHALLENGE_Server` sends them.
///
/// `N_BYTES` is 256 bit / 32 byte; generated salts default to the same 32
/// byte, the width the 1.12.1 client expects on the wire.
///
/// The group runs on SHA-1 only. Its exponent has no room for a wider digest, so
/// the default hash is not a pairing that compiles:
///
/// ```compile_fail
/// use srp6::{wow::GroupWow, Srp6, Username};
/// let srp = Srp6::<GroupWow>::default(); // H = SHA-512
/// let user = Username::new("alice").unwrap();
/// let _ = srp.generate_new_user_secrets(&user, "password");
/// ```
pub type Srp6_256 = crate::Srp6<GroupWow, crate::hash::Sha1>;
