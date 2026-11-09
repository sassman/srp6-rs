/// from https://datatracker.ietf.org/doc/html/rfc5054#appendix-A
///
/// > The 1024-, 1536-, and 2048-bit groups are taken from software
/// > developed by Tom Wu and Eugene Jhong for the Stanford SRP
/// > distribution, and subsequently proven to be prime. The larger primes
/// > are taken from [MODP], but generators have been calculated that are
/// > primitive roots of N, unlike the generators in [MODP].
/// >
/// > [MODP]        Kivinen, T. and M. Kojo, "More Modular Exponentiation
/// >               (MODP) Diffie-Hellman groups for Internet Key Exchange
/// >               (IKE)", RFC 3526, May 2003.
///
/// The moduli and generators live in [`crate::group`]; these modules keep the
/// historical `group_*_bit` paths as aliases.
macro_rules! appendix_group {
    ($module:ident, $group:ident, $alias:ident) => {
        #[allow(non_snake_case)]
        pub mod $module {
            pub use crate::group::$group;

            /// The typed SRP6 handshake for this group.
            pub type $alias = crate::Srp6<$group>;

            /// The default handshake for this group.
            pub fn values() -> $alias {
                $alias::default()
            }
        }
    };
}

appendix_group!(group_1024_bit, Group1024, Srp6_1024);
appendix_group!(group_1536_bit, Group1536, Srp6_1536);
appendix_group!(group_2048_bit, Group2048, Srp6_2048);
appendix_group!(group_3072_bit, Group3072, Srp6_3072);
appendix_group!(group_4096_bit, Group4096, Srp6_4096);
appendix_group!(group_6144_bit, Group6144, Srp6_6144);
appendix_group!(group_8192_bit, Group8192, Srp6_8192);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_historical_group_modules_expose_the_default_handshake() {
        assert_eq!(group_1024_bit::values().n_bytes(), 128);
        assert_eq!(group_1536_bit::values().n_bytes(), 192);
        assert_eq!(group_2048_bit::values().n_bytes(), 256);
        assert_eq!(group_3072_bit::values().n_bytes(), 384);
        assert_eq!(group_4096_bit::values().n_bytes(), 512);
        assert_eq!(group_6144_bit::values().n_bytes(), 768);
        assert_eq!(group_8192_bit::values().n_bytes(), 1024);
    }
}
