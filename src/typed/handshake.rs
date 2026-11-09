use super::{FieldElement, Proof, PublicKey, Salt, StrongSessionKey, Verifier};
use crate::credentials::Username;
use crate::group::{Group, GroupOps};

/// The server's stored view of one user.
pub struct UserSecrets<G: Group> {
    pub username: Username,
    pub salt: Salt,
    pub verifier: Verifier<G>,
}

/// The server's opening handshake.
#[allow(non_snake_case)]
pub struct Handshake<G: Group> {
    pub B: PublicKey<G>,
    pub g: FieldElement<G>,
    pub k: FieldElement<G>,
    pub s: Salt,
}

impl<G: Group> Handshake<G> {
    /// The server's public key `B`.
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.B
    }
}

/// What the server keeps to verify the client's proof.
#[allow(non_snake_case)]
pub struct HandshakeProofVerifier<G: GroupOps> {
    pub(super) b: G::Exponent,
    pub B: PublicKey<G>,
    pub g: FieldElement<G>,
    pub user: UserSecrets<G>,
}

impl<G: GroupOps> HandshakeProofVerifier<G> {
    /// The server's public key `B`.
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.B
    }
}

/// The client's proof.
#[allow(non_snake_case)]
pub struct HandshakeProof<G: Group> {
    pub A: PublicKey<G>,
    pub M1: Proof,
}

impl<G: Group> HandshakeProof<G> {
    /// The client's public key `A`.
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.A
    }
}

/// What the client keeps to verify the server's strong proof.
#[allow(non_snake_case)]
pub struct StrongProofVerifier<G: Group> {
    pub A: PublicKey<G>,
    pub K: StrongSessionKey,
    pub M1: Proof,
}

impl<G: Group> StrongProofVerifier<G> {
    /// The client's public key `A`.
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.A
    }
}
