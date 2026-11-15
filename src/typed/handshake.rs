use super::{FieldElement, Proof, PublicKey, Salt, StrongSessionKey, Verifier};
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

/// The server's opening handshake.
#[allow(non_snake_case)]
pub struct Handshake<G: Group> {
    pub(crate) B: PublicKey<G>,
    pub(crate) g: FieldElement<G>,
    pub(crate) k: FieldElement<G>,
    pub(crate) s: Salt,
}

impl<G: Group> Handshake<G> {
    /// Rebuilds the server's handshake on the client side from what the wire
    /// carries: `B`, `g` and `s`. The multiplier `k` is never on the wire -
    /// both sides derive it, so the caller takes it from
    /// [`crate::Srp6::multiplier`].
    #[allow(non_snake_case)]
    pub fn from_wire(B: PublicKey<G>, g: FieldElement<G>, k: FieldElement<G>, s: Salt) -> Self {
        Self { B, g, k, s }
    }

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
    pub(crate) B: PublicKey<G>,
    pub(crate) g: FieldElement<G>,
    pub(crate) user: UserSecrets<G>,
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
    pub(crate) A: PublicKey<G>,
    pub(crate) M1: Proof,
}

impl<G: Group> HandshakeProof<G> {
    /// Rebuilds the client's proof on the server side from what the wire
    /// carries: `A` and `M1`.
    #[allow(non_snake_case)]
    pub fn from_wire(A: PublicKey<G>, M1: Proof) -> Self {
        Self { A, M1 }
    }

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
    pub(crate) A: PublicKey<G>,
    pub(crate) K: StrongSessionKey,
    pub(crate) M1: Proof,
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
