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
    ($module:ident, $group:ident, $alias:ident, $generator:expr) => {
        #[allow(non_snake_case)]
        pub mod $module {
            use crate::group::Group;

            pub use crate::group::$group;

            /// The typed SRP6 handshake for this group.
            pub type $alias = crate::Srp6<$group>;

            /// The default handshake for this group.
            pub fn values() -> $alias {
                $alias::default()
            }

            /// The group's prime modulus.
            pub fn N() -> crate::primitives::PrimeModulus {
                crate::primitives::PrimeModulus::from_bytes_be(&$group.modulus_bytes())
            }

            /// The group's generator.
            pub fn g() -> crate::primitives::Generator {
                crate::primitives::Generator::from($generator)
            }
        }
    };
}

appendix_group!(group_1024_bit, Group1024, Srp6_1024, 2);
appendix_group!(group_1536_bit, Group1536, Srp6_1536, 2);
appendix_group!(group_2048_bit, Group2048, Srp6_2048, 2);
appendix_group!(group_3072_bit, Group3072, Srp6_3072, 5);
appendix_group!(group_4096_bit, Group4096, Srp6_4096, 5);
appendix_group!(group_6144_bit, Group6144, Srp6_6144, 5);
appendix_group!(group_8192_bit, Group8192, Srp6_8192, 19);
