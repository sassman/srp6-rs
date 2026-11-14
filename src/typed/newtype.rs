//! Shared trait boilerplate for the byte-backed boundary newtypes.
//!
//! Every boundary value prints as uppercase hex, debug-prints as
//! `TypeName(<hex>)`, borrows as `&[u8]`, and - where it round-trips on the
//! wire - serializes as its raw bytes. These macros derive that common surface
//! from an `as_bytes(&self) -> &[u8]` accessor, leaving each newtype file with
//! only its own construction and validation.
//!
//! Secret values (`Proof`, `StrongSessionKey`) use the redacted `Debug`
//! variant so they do not leak through logging.

/// `Display` (hex), `Debug` (`TypeName(<hex>)`) and `AsRef<[u8]>` from an
/// `as_bytes` accessor. The `<G>` arm is generic over the group marker.
macro_rules! byte_newtype_fmt {
    (<G> $ty:ident, $name:literal) => {
        impl<G: $crate::group::Group> ::std::fmt::Display for $ty<G> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                $crate::typed::hex::write_hex(f, self.as_bytes())
            }
        }

        impl<G: $crate::group::Group> ::std::fmt::Debug for $ty<G> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, concat!($name, "({})"), self)
            }
        }

        impl<G: $crate::group::Group> ::std::convert::AsRef<[u8]> for $ty<G> {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }
    };
    ($ty:ident, $name:literal) => {
        impl ::std::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                $crate::typed::hex::write_hex(f, self.as_bytes())
            }
        }

        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, concat!($name, "({})"), self)
            }
        }

        impl ::std::convert::AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }
    };
}

/// Like [`byte_newtype_fmt`] but redacts `Debug` for secret values: `Display`
/// still yields the hex on explicit request, `Debug` prints
/// `TypeName(<redacted>)` so secrets do not leak through `{:?}` or a derived
/// Debug on a surrounding struct.
macro_rules! byte_newtype_fmt_redacted {
    (<G> $ty:ident, $name:literal) => {
        impl<G: $crate::group::Group> ::std::fmt::Display for $ty<G> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                $crate::typed::hex::write_hex(f, self.as_bytes())
            }
        }

        impl<G: $crate::group::Group> ::std::fmt::Debug for $ty<G> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(concat!($name, "(<redacted>)"))
            }
        }

        impl<G: $crate::group::Group> ::std::convert::AsRef<[u8]> for $ty<G> {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }
    };
    ($ty:ident, $name:literal) => {
        impl ::std::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                $crate::typed::hex::write_hex(f, self.as_bytes())
            }
        }

        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(concat!($name, "(<redacted>)"))
            }
        }

        impl ::std::convert::AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }
    };
}

/// `Serialize` as the raw bytes. Only for the newtypes that round-trip on the
/// wire (not `Modulus`, which is a group constant).
macro_rules! byte_newtype_serialize {
    (<G> $ty:ident) => {
        impl<G: $crate::group::Group> ::serde::Serialize for $ty<G> {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::std::result::Result<S::Ok, S::Error> {
                serializer.serialize_bytes(self.as_bytes())
            }
        }
    };
    ($ty:ident) => {
        impl ::serde::Serialize for $ty {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::std::result::Result<S::Ok, S::Error> {
                serializer.serialize_bytes(self.as_bytes())
            }
        }
    };
}

pub(crate) use byte_newtype_fmt;
pub(crate) use byte_newtype_fmt_redacted;
pub(crate) use byte_newtype_serialize;

/// Construction, conversion and equality shared by the newtypes that wrap a
/// validated `FieldElement<G>` (`PublicKey`, `Verifier`). They are the same
/// shape but distinct types, so one cannot be passed where the other is
/// expected. The wrapped tuple struct and its doc are written by hand; the
/// caller applies `Display`/`Debug`/`AsRef` and `Serialize` separately, so each
/// type chooses a transparent or redacted `Debug`.
macro_rules! field_wrapper_impls {
    ($ty:ident) => {
        impl<G: $crate::group::Group> $ty<G> {
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            pub fn to_vec(&self) -> ::std::vec::Vec<u8> {
                self.0.to_vec()
            }
        }

        impl<G: $crate::group::GroupOps> $ty<G> {
            pub fn try_from_bytes(bytes: &[u8]) -> $crate::Result<Self> {
                $crate::typed::FieldElement::try_from_bytes(bytes).map(Self)
            }

            pub(crate) fn from_field(group: &G, value: &G::Field) -> Self {
                Self($crate::typed::FieldElement::from_field(group, value))
            }

            pub(crate) fn to_field(&self, group: &G) -> $crate::Result<G::Field> {
                self.0.to_field(group)
            }
        }

        impl<G: $crate::group::Group> ::std::clone::Clone for $ty<G> {
            fn clone(&self) -> Self {
                Self(::std::clone::Clone::clone(&self.0))
            }
        }

        impl<G: $crate::group::Group> ::std::cmp::PartialEq for $ty<G> {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl<G: $crate::group::Group> ::std::cmp::Eq for $ty<G> {}

        impl<G: $crate::group::Group> ::std::convert::From<$ty<G>> for ::std::vec::Vec<u8> {
            fn from(value: $ty<G>) -> Self {
                value.to_vec()
            }
        }

        impl<G: $crate::group::GroupOps> ::std::convert::TryFrom<::std::vec::Vec<u8>> for $ty<G> {
            type Error = $crate::error::Srp6Error;

            fn try_from(bytes: ::std::vec::Vec<u8>) -> $crate::Result<Self> {
                Self::try_from_bytes(&bytes)
            }
        }

        impl<G: $crate::group::GroupOps> ::std::convert::TryFrom<&[u8]> for $ty<G> {
            type Error = $crate::error::Srp6Error;

            fn try_from(bytes: &[u8]) -> $crate::Result<Self> {
                Self::try_from_bytes(bytes)
            }
        }

        impl<G: $crate::group::GroupOps> $crate::typed::FromHexString for $ty<G> {
            fn try_from_hex(hex: &str) -> $crate::Result<Self> {
                Self::try_from_bytes(&$crate::typed::hex::decode_hex(hex)?)
            }
        }

        impl<'de, G: $crate::group::GroupOps> ::serde::Deserialize<'de> for $ty<G> {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::std::result::Result<Self, D::Error> {
                let bytes =
                    <::std::vec::Vec<u8> as ::serde::Deserialize>::deserialize(deserializer)?;
                Self::try_from_bytes(&bytes).map_err(::serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use field_wrapper_impls;
