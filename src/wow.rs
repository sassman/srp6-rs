/*!
The World of Warcraft 1.12.1 (build 5875) group.

Behind the `wow-1-12-1` feature, alongside the rest of that client's flavour:
`k = 3` and uppercased credentials (`crate::primitives`).

This group is not safe for anything else. `N` is 256 bit, far below the
[RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
groups in [`crate::rfc_5054_appendix_a`], and the flavour hashes with SHA-1.
It exists to talk to a client that shipped in 2006.
*/

pub use crate::group::GroupWow;

/// The 1.12.1 client's handshake: `g = 7` and a 256-bit `N`, as
/// `CMD_AUTH_LOGON_CHALLENGE_Server` sends them.
///
/// [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and
/// [`Salt`][crate::primitives::Salt] `s` are both 256 bit / 32 byte.
pub type Srp6_256 = crate::Srp6<GroupWow>;
