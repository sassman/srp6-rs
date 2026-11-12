use rand::{rng, RngExt};

use super::steps;
use super::{
    FieldElement, Handshake, HandshakeProof, HandshakeProofVerifier, Proof, PublicKey, Salt,
    SaltBytes, StrongProofVerifier, StrongSessionKey, UserSecrets, Verifier,
};
use crate::credentials::{ClearTextPasswordRef, Username};
use crate::group::{Group, GroupOps};
use crate::{error::Srp6Error, Result};

/// The SRP6 handshake for one closed group.
pub struct Srp6<G: Group> {
    group: G,
    salt_bytes: usize,
}

impl<G: Group> Srp6<G> {
    pub fn new(group: G) -> Self {
        Self {
            group,
            salt_bytes: G::DEFAULT_SALT_BYTES,
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

impl<G: GroupOps> Default for Srp6<G> {
    fn default() -> Self {
        Self::new(G::default())
    }
}

impl<G: GroupOps> Srp6<G> {
    /// Creates a salt and password verifier for a new user.
    pub fn generate_new_user_secrets(
        &self,
        username: &Username,
        password: ClearTextPasswordRef,
    ) -> (Salt, Verifier<G>) {
        let salt: Vec<u8> = rng().random_iter().take(self.salt_bytes).collect();
        self.generate_new_user_secrets_with_salt(username, password, Salt::from(salt))
    }

    pub(crate) fn generate_new_user_secrets_with_salt(
        &self,
        username: &Username,
        password: ClearTextPasswordRef,
        salt: Salt,
    ) -> (Salt, Verifier<G>) {
        let x = steps::private_key_x(&self.group, username, password, &salt);
        let verifier = self.group.field_pow(&self.group.generator(), &x);

        (salt, Verifier::from_field(&self.group, &verifier))
    }

    /// Starts the handshake for an existing user.
    ///
    /// # Errors
    /// Returns [`Srp6Error::InvalidFieldElement`] if the stored verifier or the
    /// group multiplier does not decode to a non-zero field element.
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
        let k = self.group.multiplier()?;
        let g_b = self.group.field_pow(&g, &b);
        let k_v = self.group.field_mul(&k, &verifier_field);
        let b_pub = self.group.field_add(&k_v, &g_b);

        // Encode each boundary value once and share it between the two structs.
        let b_public = PublicKey::from_field(&self.group, &b_pub);
        let g = FieldElement::from_field(&self.group, &g);
        let k = FieldElement::from_field(&self.group, &k);

        let handshake = Handshake {
            B: b_public.clone(),
            g: g.clone(),
            k,
            s: salt.clone(),
        };
        let verifier = HandshakeProofVerifier {
            b,
            B: b_public,
            g,
            user: UserSecrets {
                username: username.clone(),
                salt,
                verifier,
            },
        };

        Ok((handshake, verifier))
    }

    /// Verifies the client's proof and returns the strong proof `M2`.
    pub fn verify_proof(
        &self,
        verifier: &HandshakeProofVerifier<G>,
        proof: &HandshakeProof<G>,
    ) -> Result<Proof> {
        let a_field = proof.A.to_field(&self.group)?;
        let verifier_field = verifier.user.verifier.to_field(&self.group)?;

        let u = steps::scrambler_u(&self.group, &proof.A, &verifier.B);
        if steps::is_zero_exponent(&self.group, &u) {
            return Err(Srp6Error::InvalidScrambler);
        }
        let v_u = self.group.field_pow(&verifier_field, &u);
        let a_vu = self.group.field_mul(&a_field, &v_u);
        let s = self.group.field_pow(&a_vu, &verifier.b);
        let s = FieldElement::from_field(&self.group, &s);
        let k = steps::strong_session_key(&s);

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

        Ok(steps::proof_m2(&proof.A, &m1, &k))
    }

    /// Calculates the client's proof and its strong-proof verifier.
    pub fn calculate_proof(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: ClearTextPasswordRef,
    ) -> Result<(HandshakeProof<G>, StrongProofVerifier<G>)> {
        let a_exp = self.group.random_exponent();
        self.calculate_proof_with_a(handshake, username, password, a_exp)
    }

    pub(crate) fn calculate_proof_with_a(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: ClearTextPasswordRef,
        a_exp: G::Exponent,
    ) -> Result<(HandshakeProof<G>, StrongProofVerifier<G>)> {
        let b_field = handshake.B.to_field(&self.group)?;
        let g_field = handshake.g.to_field(&self.group)?;
        let k_field = handshake.k.to_field(&self.group)?;

        let a_field = self.group.field_pow(&self.group.generator(), &a_exp);
        let a_public = PublicKey::from_field(&self.group, &a_field);

        let u = steps::scrambler_u(&self.group, &a_public, &handshake.B);
        if steps::is_zero_exponent(&self.group, &u) {
            return Err(Srp6Error::InvalidScrambler);
        }
        let x = steps::private_key_x(&self.group, username, password, &handshake.s);
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
        let strong_key = steps::strong_session_key(&s);

        let m1 = steps::proof_m1(
            &self.group,
            username,
            &handshake.s,
            &a_public,
            &handshake.B,
            &strong_key,
        );

        let proof = HandshakeProof {
            A: a_public.clone(),
            M1: m1,
        };
        let verifier = StrongProofVerifier {
            A: a_public,
            K: strong_key,
            M1: m1,
        };

        Ok((proof, verifier))
    }

    /// Verifies the server's strong proof.
    pub fn verify_strong_proof(
        &self,
        verifier: &StrongProofVerifier<G>,
        m2: &Proof,
    ) -> Result<StrongSessionKey> {
        let expected = steps::proof_m2(&verifier.A, &verifier.M1, &verifier.K);
        if !expected.ct_eq(m2) {
            return Err(Srp6Error::InvalidStrongProof(*m2));
        }

        Ok(verifier.K)
    }
}
