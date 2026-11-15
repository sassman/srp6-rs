//! Whether a group's drawn proof must encode unambiguously at a fixed wire width.
//!
//! The WoW 1.12.1 wire sends each SRP value at the group's fixed width, and the
//! stock client and vmangos hash a value with a zero in a significant byte
//! differently. So a `GroupWow` draw whose `A`, `K` or `M1` has a zero high-order
//! byte, or whose premaster `S` has a zero low-order one (the client interleave
//! strips it), is ambiguous and the ephemeral must be redrawn. The RFC 5054
//! groups pad big-endian and share one encoding, so they never redraw.
//!
//! The policy lives beside the handshake rather than on the group so the group
//! trait stays about arithmetic; every closed group names its policy here.

use crate::group::*;

/// A closed group's wire-encoding policy: whether a drawn proof is rejected when
/// it does not encode unambiguously at the group's fixed width.
pub trait WireStable {
    /// `true` only for a flavour whose fixed-width wire cannot represent a zero
    /// pad byte without changing how the value hashes.
    const AMBIGUITY_CHECKED: bool;
}

macro_rules! wire_stable {
    ($group:ident, $checked:expr) => {
        impl WireStable for $group {
            const AMBIGUITY_CHECKED: bool = $checked;
        }
    };
}

#[cfg(feature = "weak")]
wire_stable!(Group1024, false);
#[cfg(feature = "weak")]
wire_stable!(Group1536, false);
wire_stable!(Group2048, false);
wire_stable!(Group3072, false);
wire_stable!(Group4096, false);
wire_stable!(Group6144, false);
wire_stable!(Group8192, false);
#[cfg(feature = "wow-1-12-1")]
wire_stable!(GroupWow, true);
