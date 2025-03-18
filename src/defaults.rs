/*!
default prime modulus and generator numbers taken from [RFC5054 Appendix A],
so they can be treated as vetted and safe.

## Usage:
```rust
use srp6::{Srp6_4096, HostAPI};

let srp = Srp6_4096::default();
let (_salt_s, _verifier_v) = srp.generate_new_user_secrets("Bob", "secret-password");
```

then you can alias a type for a convienice e.g.:
```rust
use srp6::{Srp6, Generator, TryInto};

pub type MyCustomSrp6 = Srp6<2, 2>;
pub fn my_custom_srp6_new() -> MyCustomSrp6 {
    MyCustomSrp6::new(
        Generator::from(5),
        "FE27".try_into().unwrap(),
    ).unwrap()
}

let my_srp = my_custom_srp6_new();
```

[RFC5054 Appendix A]: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A
*/

use crate::rfc_5054_appendix_a::{
    group_2048_bit, group_3072_bit, group_4096_bit, group_6144_bit, group_8192_bit,
};

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 2048 bit / 256 byte.
pub use group_2048_bit::Srp6_2048;

impl Default for Srp6_2048 {
    fn default() -> Self {
        group_2048_bit::values()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 3072 bit / 384 byte.
pub use group_3072_bit::Srp6_3072;

impl Default for Srp6_3072 {
    fn default() -> Self {
        group_3072_bit::values()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 4096 bit / 512 byte.
pub use group_4096_bit::Srp6_4096;

impl Default for Srp6_4096 {
    fn default() -> Self {
        group_4096_bit::values()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 6144 bit / 768 byte.
pub use group_6144_bit::Srp6_6144;

impl Default for Srp6_6144 {
    fn default() -> Self {
        group_6144_bit::values()
    }
}

/// length of [`PrimeModulus`][crate::primitives::PrimeModulus] `N` and [`Salt`][crate::primitives::Salt] `s` is 8192 bit / 1024 byte.
pub use group_8192_bit::Srp6_8192;

impl Default for Srp6_8192 {
    fn default() -> Self {
        group_8192_bit::values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_ensure_key_lengths_are_as_expected() {
        let srp = Srp6_2048::default();
        assert_eq!(srp.N.num_bytes() as u32, 2048 / 8);

        let srp = Srp6_3072::default();
        assert_eq!(srp.N.num_bytes() as u32, 3072 / 8);
    }
}
