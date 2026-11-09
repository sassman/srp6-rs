use super::{FieldElement, Proof, PublicKey, Salt, StrongSessionKey, Verifier};
use crate::credentials::Username;
use crate::group::{Group, GroupOps};

/// The server's stored view of one user.
pub struct UserSecrets<G: Group> {
    pub username: Username,
    pub salt: Salt,
    pub verifier: Verifier<G>,
}

impl<G: Group> UserSecrets<G> {
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
    #[doc(alias = "B")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.B
    }

    /// The generator `g`.
    #[doc(alias = "g")]
    pub fn generator(&self) -> &FieldElement<G> {
        &self.g
    }

    /// The multiplier `k`.
    #[doc(alias = "k")]
    pub fn multiplier(&self) -> &FieldElement<G> {
        &self.k
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
    pub B: PublicKey<G>,
    pub g: FieldElement<G>,
    pub user: UserSecrets<G>,
}

impl<G: GroupOps> HandshakeProofVerifier<G> {
    /// The server's public key `B`.
    #[doc(alias = "B")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.B
    }

    /// The generator `g`.
    #[doc(alias = "g")]
    pub fn generator(&self) -> &FieldElement<G> {
        &self.g
    }

    /// The stored user secrets.
    pub fn user(&self) -> &UserSecrets<G> {
        &self.user
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
    #[doc(alias = "A")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.A
    }

    /// The client's proof `M1`.
    #[doc(alias = "M1")]
    pub fn proof(&self) -> &Proof {
        &self.M1
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
    #[doc(alias = "A")]
    pub fn public_key(&self) -> &PublicKey<G> {
        &self.A
    }

    /// The strong session key `K`.
    #[doc(alias = "K")]
    pub fn session_key(&self) -> &StrongSessionKey {
        &self.K
    }

    /// The client's proof `M1`.
    #[doc(alias = "M1")]
    pub fn proof(&self) -> &Proof {
        &self.M1
    }
}
