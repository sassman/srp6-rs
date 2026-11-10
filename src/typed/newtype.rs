//! Shared trait boilerplate for the byte-backed boundary newtypes.
//!
//! Every boundary value prints as uppercase hex, debug-prints as
//! `TypeName(<hex>)`, borrows as `&[u8]`, and - where it round-trips on the
//! wire - serializes as its raw bytes. These macros derive that common surface
//! from an `as_bytes(&self) -> &[u8]` accessor, leaving each newtype file with
//! only its own construction and validation.
//!
//! `StrongSessionKey` is deliberately wired by hand: its `Debug` is redacted.

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
pub(crate) use byte_newtype_serialize;
