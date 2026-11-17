use super::{Proof, PublicKey, Salt, StrongSessionKey, Verifier};
use crate::credentials::Username;
use crate::group::{Group, GroupOps};

/// The server's stored view of one user.
pub struct UserSecrets<G: Group> {
    pub(crate) username: Username,
    pub(crate) salt: Salt,
    pub(crate) verifier: Verifier<G>,
}

impl<G: Group> UserSecrets<G> {
    /// Assembles the stored view of a user, e.g. after loading the salt `s`
    /// and verifier `v` from a database.
    pub fn new(username: Username, salt: Salt, verifier: Verifier<G>) -> Self {
        Self {
            username,
            salt,
            verifier,
        }
    }

    /// The username `I`.
    #[doc(alias = "I")]
    pub fn username(&self) -> &Username {
        &self.username
    }

    /// The salt `s`.
    #[doc(alias = "s")]
    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    /// The password verifier `v`.
    #[doc(alias = "v")]
    pub fn verifier(&self) -> &Verifier<G> {
        &self.verifier
    }
}

/// The server's opening handshake: what is particular to one login. The group
/// (`N`, `g`, `k`) is not part of it - both sides hold it, and a client that
/// took it from the peer could be handed a weak one.
#[allow(non_snake_case)]
pub struct Handshake<G: Group> {
    pub(crate) B: PublicKey<G>,
    pub(crate) s: Salt,
}

impl<G: Group> Handshake<G> {
    /// Rebuilds the server's handshake on the client side from what the wire
    /// carries of it: `B` and `s`. A wire that also names the group is checked
    /// with [`crate::Srp6::check_group`].
    #[allow(non_snake_case)]
    pub fn from_wire(B: PublicKey<G>, s: Salt) -> Self {
        Self { B, s }
    }

    /// The server's public key `B`.
    #[doc(alias = "B")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.B
    }

    /// The salt `s`.
    #[doc(alias = "s")]
    pub fn salt(&self) -> &Salt {
        &self.s
    }
}

/// What the server keeps to verify the client's proof.
#[allow(non_snake_case)]
pub struct HandshakeProofVerifier<G: GroupOps> {
    pub(super) b: G::Exponent,
    pub(crate) B: PublicKey<G>,
    pub(crate) user: UserSecrets<G>,
}

impl<G: GroupOps> HandshakeProofVerifier<G> {
    /// The server's public key `B`.
    #[doc(alias = "B")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.B
    }

    /// The stored user secrets.
    pub fn user(&self) -> &UserSecrets<G> {
        &self.user
    }
}

/// The client's proof.
#[allow(non_snake_case)]
pub struct HandshakeProof<G: Group, H> {
    pub(crate) A: PublicKey<G>,
    pub(crate) M1: Proof<H>,
}

impl<G: Group, H> HandshakeProof<G, H> {
    /// Rebuilds the client's proof on the server side from what the wire
    /// carries: `A` and `M1`.
    #[allow(non_snake_case)]
    pub fn from_wire(A: PublicKey<G>, M1: Proof<H>) -> Self {
        Self { A, M1 }
    }

    /// The client's public key `A`.
    #[doc(alias = "A")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.A
    }

    /// The client's proof `M1`.
    #[doc(alias = "M1")]
    pub fn proof(&self) -> &Proof<H> {
        &self.M1
    }
}

/// What the client keeps to verify the server's strong proof.
#[allow(non_snake_case)]
pub struct StrongProofVerifier<G: Group, H> {
    pub(crate) A: PublicKey<G>,
    pub(crate) K: StrongSessionKey<H>,
    pub(crate) M1: Proof<H>,
}

impl<G: Group, H> StrongProofVerifier<G, H> {
    /// The client's public key `A`.
    #[doc(alias = "A")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.A
    }

    /// The strong session key `K`.
    #[doc(alias = "K")]
    pub fn session_key(&self) -> &StrongSessionKey<H> {
        &self.K
    }

    /// The client's proof `M1`.
    #[doc(alias = "M1")]
    pub fn proof(&self) -> &Proof<H> {
        &self.M1
    }
}

/// What a client holds once it has answered a handshake: the proof to send, and
/// what verifies the server's answer to it.
pub struct ClientProof<G: Group, H> {
    /// `A` and `M1`, for the server.
    pub proof: HandshakeProof<G, H>,
    /// Kept by the client for [`crate::Srp6::verify_strong_proof`].
    pub verifier: StrongProofVerifier<G, H>,
}

/// What a server holds once a client's proof verified.
pub struct ServerProof<H> {
    /// The strong proof `M2`, for the client.
    #[doc(alias = "M2")]
    pub strong_proof: Proof<H>,
    /// The session key `K` both sides now share.
    #[doc(alias = "K")]
    pub session_key: StrongSessionKey<H>,
}

// Hand-written rather than derived: consumers hold these in their own
// `#[derive(Debug)]` state, so the impls must exist - and the ephemeral `b`
// carries no Debug bound and must never reach a log line anyway. The field
// types guard themselves (`Verifier`, `Proof` and `StrongSessionKey` redact),
// so delegation leaks nothing.

impl<G: Group> std::fmt::Debug for Handshake<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("B", &self.B)
            .field("s", &self.s)
            .finish()
    }
}

impl<G: Group> std::fmt::Debug for UserSecrets<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserSecrets")
            .field("username", &self.username)
            .field("salt", &self.salt)
            .field("verifier", &self.verifier)
            .finish()
    }
}

impl<G: GroupOps> std::fmt::Debug for HandshakeProofVerifier<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeProofVerifier")
            .field("b", &"<redacted>")
            .field("B", &self.B)
            .field("user", &self.user)
            .finish()
    }
}

impl<G: Group, H> std::fmt::Debug for HandshakeProof<G, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeProof")
            .field("A", &self.A)
            .field("M1", &self.M1)
            .finish()
    }
}

impl<G: Group, H> std::fmt::Debug for StrongProofVerifier<G, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrongProofVerifier")
            .field("A", &self.A)
            .field("K", &self.K)
            .field("M1", &self.M1)
            .finish()
    }
}

impl<G: Group, H> std::fmt::Debug for ClientProof<G, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProof")
            .field("proof", &self.proof)
            .field("verifier", &self.verifier)
            .finish()
    }
}

impl<H> std::fmt::Debug for ServerProof<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerProof")
            .field("strong_proof", &self.strong_proof)
            .field("session_key", &self.session_key)
            .finish()
    }
}
