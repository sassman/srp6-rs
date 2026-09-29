/*!
The World of Warcraft 1.12.1 (build 5875) group.

Behind the `wow-1-12-1` feature, alongside the rest of that client's flavour:
`k = 3` and uppercased credentials (`crate::primitives`).

This group is not safe for anything else. `N` is 256 bit, far below the
[RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
groups in [`crate::rfc_5054_appendix_a`], and the flavour hashes with SHA-1.
It exists to talk to a client that shipped in 2006.
*/
use crate::api::host::Srp6;
use crate::primitives::{Generator, PrimeModulus};

/// The 1.12.1 client's group: `g = 7` and a 256-bit `N`, as
/// `CMD_AUTH_LOGON_CHALLENGE_Server` sends them.
///
/// [`PrimeModulus`] `N` and [`Salt`][crate::primitives::Salt] `s` are both
/// 256 bit / 32 byte.
pub type Srp6_256 = Srp6<32, 32>;

impl Default for Srp6_256 {
    fn default() -> Self {
        Self::new(
            Generator::from(7),
            PrimeModulus::from_hex_str_be(
                "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
            )
            .unwrap(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_ensure_key_length_is_as_expected() {
        let srp = Srp6_256::default();
        assert_eq!(srp.N.num_bytes(), 256 / 8);
    }

    /// The generator is 7, not the 2 that the RFC 5054 groups use.
    #[test]
    fn should_use_the_clients_generator() {
        let srp = Srp6_256::default();
        assert_eq!(srp.g, Generator::from(7));
    }
}
