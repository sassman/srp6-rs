use crate::api::host::Srp6;
use crate::primitives::{Generator, PrimeModulus};
use crate::rfc_5054_appendix_a::group_1024_bit;

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 256 bit / 32 byte.
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

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 512 bit / 64 byte.
pub type Srp6_512 = Srp6<64, 64>;

impl Default for Srp6_512 {
    fn default() -> Self {
        Self::new(
            Generator::from(7),
            PrimeModulus::from_hex_str_be(
                "D58B60A281533E85DA01C6943F8EAF5A14737F8F701788B4611A3A88D5A6A0A0
                 E3EA3DA917EF8D036BA79706DAC9EB261E469D02B44998B88F3B06EACFF96D7B",
            )
            .unwrap(),
        )
        .unwrap()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 1024 bit / 128 byte.
/// taken from the 1024-bit group at [RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
pub use group_1024_bit::Srp6_1024;

impl Default for Srp6_1024 {
    fn default() -> Self {
        group_1024_bit::values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_ensure_key_length_is_as_expected() {
        let srp = Srp6_256::default();
        assert_eq!(srp.N.num_bytes(), 256 / 8);

        let srp = Srp6_512::default();
        assert_eq!(srp.N.num_bytes() as u32, 512 / 8);

        let srp = Srp6_1024::default();
        assert_eq!(srp.N.num_bytes() as u32, 1024 / 8);
    }
}
