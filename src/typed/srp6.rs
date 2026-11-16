use std::marker::PhantomData;

use rand::{rng, RngExt};

use super::steps;
use super::{
    ClientEphemeral, ClientProof, FieldElement, Handshake, HandshakeProof, HandshakeProofVerifier,
    Proof, PublicKey, Salt, SaltBytes, ServerProof, StrongProofVerifier, StrongSessionKey,
    UserSecrets, Verifier,
};
use crate::credentials::{ClearTextPasswordRef, Username};
use crate::group::{Group, GroupOps};
use crate::hash::{DefaultHash, HashFor};
use crate::{error::Srp6Error, Result};

/// How often [`Srp6::calculate_proof`] redraws an ambiguous ephemeral before it
/// gives up, so the loop is bounded. Nearly every draw passes, so a run this
/// long only happens against values chosen to make it.
#[cfg(feature = "wow-1-12-1")]
const AMBIGUOUS_REDRAWS: u32 = 64;

/// Whether a WoW draw encodes unambiguously at the fixed wire width. The
/// high-order byte is last in the little-endian wire, so a zero there makes `A`,
/// `K` or `M1` ambiguous; for the premaster `S` it is the low byte the client
/// interleave would strip.
#[cfg(feature = "wow-1-12-1")]
fn wire_stable(a: &[u8], s: &[u8], k: &[u8], m1: &[u8]) -> bool {
    let high_nonzero = |bytes: &[u8]| bytes.last().is_some_and(|&byte| byte != 0);
    high_nonzero(a)
        && s.first().is_some_and(|&byte| byte != 0)
        && high_nonzero(k)
        && high_nonzero(m1)
}

/// The SRP6 handshake for one closed group and hash. The hash `H` defaults to
/// SHA-512; a consumer can name another for a different flavour.
pub struct Srp6<G: Group, H = DefaultHash> {
    group: G,
    salt_bytes: usize,
    _hash: PhantomData<H>,
}

impl<G: Group, H> Srp6<G, H> {
    pub fn new(group: G) -> Self {
        Self {
            group,
            salt_bytes: G::DEFAULT_SALT_BYTES,
            _hash: PhantomData,
        }
    }

    /// Overrides the salt width [`Self::generate_new_user_secrets`] draws.
    ///
    /// Systemic, not per-user: salts already stored keep working at any
    /// length, so this only shapes registrations made through this instance.
    pub fn with_salt(mut self, salt: SaltBytes) -> Self {
        self.salt_bytes = salt.get();
        self
    }

    /// The modulus width in bytes, as declared by the group.
    pub fn n_bytes(&self) -> usize {
        G::N_BYTES
    }

    /// The effective width of generated salts in bytes: the group's default,
    /// or the [`Self::with_salt`] override.
    pub fn salt_bytes(&self) -> usize {
        self.salt_bytes
    }

    /// The prime modulus `N`, as declared by the group.
    ///
    /// `N` is part of the handshake the server hands the client, so it is
    /// reachable from the driver rather than only from the group type.
    #[doc(alias = "N")]
    pub fn modulus(&self) -> crate::Modulus<G> {
        self.group.modulus()
    }
}

impl<G: GroupOps, H> Default for Srp6<G, H> {
    fn default() -> Self {
        Self::new(G::default())
    }
}

impl<G: GroupOps, H: HashFor<G>> Srp6<G, H> {
    /// The multiplier `k`, derived from the group. It is never on the wire.
    #[doc(alias = "k")]
    pub fn multiplier(&self) -> FieldElement<G> {
        let k = steps::multiplier::<G, H>(&self.group);
        FieldElement::from_field(&self.group, &k)
    }

    /// The generator `g`, as declared by the group: what a server sends on a wire
    /// that names the group.
    #[doc(alias = "g")]
    pub fn generator(&self) -> FieldElement<G> {
        FieldElement::from_field(&self.group, &self.group.generator())
    }

    /// Checks a group a peer named against this one, for a wire that carries `N`
    /// and `g`. `modulus` must be `N` at its full width and `generator` may come
    /// padded or minimal, both in the group's byte order.
    ///
    /// The handshake never computes with a peer's group, so skipping this is not
    /// unsafe; it tells a server that speaks another group from a wrong password.
    ///
    /// # Errors
    /// [`Srp6Error::GroupMismatch`] if either differs.
    pub fn check_group(&self, modulus: &[u8], generator: &[u8]) -> Result<()> {
        let same_generator = self
            .group
            .field_from_bytes(generator)
            .is_some_and(|g| self.group.field_to_bytes(&g) == self.generator().as_bytes());
        if modulus != self.modulus().as_bytes() || !same_generator {
            return Err(Srp6Error::GroupMismatch);
        }
        Ok(())
    }

    /// Creates a salt and password verifier for a new user.
    pub fn generate_new_user_secrets(
        &self,
        username: &Username,
        password: ClearTextPasswordRef,
    ) -> (Salt, Verifier<G>) {
        let salt: Vec<u8> = rng().random_iter().take(self.salt_bytes).collect();
        self.generate_new_user_secrets_with_salt(username, password, Salt::from(salt))
    }

    /// [`Self::generate_new_user_secrets`] for a salt the caller already holds:
    /// an account imported with its salt, or one whose salt must satisfy a rule
    /// of the wire it travels on. The salt comes back unchanged, and is taken as
    /// it is: no floor on its length applies here, so a short or repeated salt is
    /// the caller's to rule out.
    pub fn generate_new_user_secrets_with_salt(
        &self,
        username: &Username,
        password: ClearTextPasswordRef,
        salt: Salt,
    ) -> (Salt, Verifier<G>) {
        let x = steps::private_key_x::<_, H>(&self.group, username, password, &salt);
        let verifier = self.group.field_pow(&self.group.generator(), &x);

        (salt, Verifier::from_field(&self.group, &verifier))
    }

    /// Starts the handshake for an existing user.
    ///
    /// # Errors
    /// Returns [`Srp6Error::InvalidFieldElement`] if the stored verifier does not
    /// decode to a non-zero field element.
    pub fn start_handshake(
        &self,
        username: &Username,
        salt: Salt,
        verifier: Verifier<G>,
    ) -> Result<(Handshake<G>, HandshakeProofVerifier<G>)> {
        let b = self.group.random_exponent();
        self.start_handshake_with_b(username, salt, verifier, b)
    }

    pub(crate) fn start_handshake_with_b(
        &self,
        username: &Username,
        salt: Salt,
        verifier: Verifier<G>,
        b: G::Exponent,
    ) -> Result<(Handshake<G>, HandshakeProofVerifier<G>)> {
        let verifier_field = verifier.to_field(&self.group)?;
        let g = self.group.generator();
        let k = steps::multiplier::<G, H>(&self.group);
        let g_b = self.group.field_pow(&g, &b);
        let k_v = self.group.field_mul(&k, &verifier_field);
        let b_pub = self.group.field_add(&k_v, &g_b);

        // Encode the boundary value once and share it between the two structs.
        let b_public = PublicKey::from_field(&self.group, &b_pub);

        let handshake = Handshake {
            B: b_public.clone(),
            s: salt.clone(),
        };
        let verifier = HandshakeProofVerifier {
            b,
            B: b_public,
            user: UserSecrets {
                username: username.clone(),
                salt,
                verifier,
            },
        };

        Ok((handshake, verifier))
    }

    /// Verifies the client's proof. The answer carries the strong proof `M2` and
    /// the shared session key `K` - a server may encrypt with `K` from the first
    /// packet after login, so it leaves the handshake here.
    pub fn verify_proof(
        &self,
        verifier: &HandshakeProofVerifier<G>,
        proof: &HandshakeProof<G, H>,
    ) -> Result<ServerProof<H>> {
        let a_field = proof.A.to_field(&self.group)?;
        let verifier_field = verifier.user.verifier.to_field(&self.group)?;

        let u = steps::scrambler_u::<_, H>(&self.group, &proof.A, &verifier.B);
        if steps::is_zero_exponent(&self.group, &u) {
            return Err(Srp6Error::InvalidScrambler);
        }
        let v_u = self.group.field_pow(&verifier_field, &u);
        let a_vu = self.group.field_mul(&a_field, &v_u);
        let s = self.group.field_pow(&a_vu, &verifier.b);
        let s = FieldElement::from_field(&self.group, &s);
        let k = steps::strong_session_key::<_, H>(&s);

        let m1 = steps::proof_m1(
            &self.group,
            &verifier.user.username,
            &verifier.user.salt,
            &proof.A,
            &verifier.B,
            &k,
        );
        if !m1.ct_eq(&proof.M1) {
            return Err(Srp6Error::InvalidProof);
        }

        Ok(ServerProof {
            strong_proof: steps::proof_m2(&proof.A, &m1, &k),
            session_key: k,
        })
    }

    /// Calculates the client's proof and its strong-proof verifier, drawing a
    /// fresh ephemeral `a`.
    pub fn calculate_proof(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: ClearTextPasswordRef,
    ) -> Result<ClientProof<G, H>> {
        // The draw is this method's own, so an ambiguous one is redrawn here: a
        // caller has no ephemeral to change.
        #[cfg(feature = "wow-1-12-1")]
        for _ in 1..AMBIGUOUS_REDRAWS {
            let a_exp = self.group.random_exponent();
            let drawn = self.proof_for_exponent(handshake, username, password, a_exp);
            if !matches!(drawn, Err(Srp6Error::AmbiguousEncoding)) {
                return drawn;
            }
        }

        let a_exp = self.group.random_exponent();
        self.proof_for_exponent(handshake, username, password, a_exp)
    }

    /// [`Self::calculate_proof`] with the ephemeral `a` supplied, for a caller that
    /// must control the draw.
    pub fn calculate_proof_with_a(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: ClearTextPasswordRef,
        a: &ClientEphemeral<G>,
    ) -> Result<ClientProof<G, H>> {
        let a_exp = self.group.exponent_from_bytes(&a.bytes);
        self.proof_for_exponent(handshake, username, password, a_exp)
    }

    fn proof_for_exponent(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: ClearTextPasswordRef,
        a_exp: G::Exponent,
    ) -> Result<ClientProof<G, H>> {
        let b_field = handshake.B.to_field(&self.group)?;
        let g_field = self.group.generator();
        let k_field = steps::multiplier::<G, H>(&self.group);

        let a_field = self.group.field_pow(&g_field, &a_exp);
        let a_public = PublicKey::from_field(&self.group, &a_field);

        let u = steps::scrambler_u::<_, H>(&self.group, &a_public, &handshake.B);
        if steps::is_zero_exponent(&self.group, &u) {
            return Err(Srp6Error::InvalidScrambler);
        }
        let x = steps::private_key_x::<_, H>(&self.group, username, password, &handshake.s);
        let ux = self.group.exponent_mul(&u, &x);
        let exp = self.group.exponent_add(&a_exp, &ux);

        let g_x = self.group.field_pow(&g_field, &x);
        let k_gx = self.group.field_mul(&k_field, &g_x);
        let base = self.group.field_sub(&b_field, &k_gx);
        let s = self.group.field_pow(&base, &exp);
        let s = FieldElement::from_field(&self.group, &s);
        // A malicious server can send B = k*v, forcing base = 0 and S = 0.
        // `from_field` does not re-reject zero, so guard before deriving K.
        if s.as_bytes().iter().all(|&byte| byte == 0) {
            return Err(Srp6Error::InvalidPremaster);
        }
        let strong_key = steps::strong_session_key::<_, H>(&s);

        let m1 = steps::proof_m1(
            &self.group,
            username,
            &handshake.s,
            &a_public,
            &handshake.B,
            &strong_key,
        );

        // WoW sends each value at the group's fixed width, and a zero in a
        // significant byte hashes differently on the stock client. A flavour that
        // cannot represent it rejects the draw so the caller redraws `a`. The
        // high-order byte is last in the little-endian wire; the premaster's is
        // the low byte the interleave strips.
        #[cfg(feature = "wow-1-12-1")]
        if G::AMBIGUITY_CHECKED
            && !wire_stable(
                a_public.as_bytes(),
                s.as_bytes(),
                strong_key.as_bytes(),
                m1.as_bytes(),
            )
        {
            return Err(Srp6Error::AmbiguousEncoding);
        }

        let proof = HandshakeProof {
            A: a_public.clone(),
            M1: m1.clone(),
        };
        let verifier = StrongProofVerifier {
            A: a_public,
            K: strong_key,
            M1: m1,
        };

        Ok(ClientProof { proof, verifier })
    }

    /// Verifies the server's strong proof.
    pub fn verify_strong_proof(
        &self,
        verifier: &StrongProofVerifier<G, H>,
        m2: &Proof<H>,
    ) -> Result<StrongSessionKey<H>> {
        let expected = steps::proof_m2(&verifier.A, &verifier.M1, &verifier.K);
        if !expected.ct_eq(m2) {
            return Err(Srp6Error::InvalidStrongProof(m2.to_vec()));
        }

        Ok(verifier.K.clone())
    }
}
