use std::marker::PhantomData;

use rand::{rng, RngExt};

use crate::group::Group;
use crate::{error::Srp6Error, Result};

/// A client's private ephemeral `a`, for a caller that must control the draw
/// ([`crate::Srp6::calculate_proof_with_a`]).
///
/// It is a secret for the length of one handshake: an `a` that can be guessed
/// gives the session away, so bytes passed in must come from a cryptographic
/// source. [`std::fmt::Debug`] is redacted and nothing hands the bytes back.
pub struct ClientEphemeral<G: Group> {
    pub(crate) bytes: Box<[u8]>,
    _group: PhantomData<G>,
}

impl<G: Group> ClientEphemeral<G> {
    /// Takes `bytes` in the group's byte order.
    ///
    /// # Errors
    /// [`Srp6Error::InvalidEphemeral`] for none, more than the modulus holds, or
    /// zero - which makes `A = 1` and the secret the server's to compute.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > G::N_BYTES || bytes.iter().all(|byte| *byte == 0) {
            return Err(Srp6Error::InvalidEphemeral { max: G::N_BYTES });
        }
        Ok(Self {
            bytes: bytes.into(),
            _group: PhantomData,
        })
    }

    /// Draws one at the modulus width.
    pub fn random() -> Self {
        loop {
            let bytes: Vec<u8> = rng().random_iter().take(G::N_BYTES).collect();
            if let Ok(ephemeral) = Self::try_from_bytes(&bytes) {
                return ephemeral;
            }
        }
    }
}

impl<G: Group> std::fmt::Debug for ClientEphemeral<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientEphemeral(<redacted>)")
    }
}
