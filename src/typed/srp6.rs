use rand::{rng, RngExt};

use super::steps;
use super::{
    FieldElement, Handshake, HandshakeProof, HandshakeProofVerifier, Proof, PublicKey, Salt,
    StrongProofVerifier, StrongSessionKey, UserSecrets, Verifier,
};
use crate::credentials::{ClearTextPasswordRef, Username};
use crate::group::{Group, GroupOps};
use crate::{error::Srp6Error, Result};

/// The SRP6 handshake for one closed group.
pub struct Srp6<G: Group> {
    group: G,
}

impl<G: Group> Srp6<G> {
    pub fn new(group: G) -> Self {
        Self { group }
    }

    /// The modulus width in bytes, as declared by the group.
    pub fn n_bytes(&self) -> usize {
        G::N_BYTES
    }

    /// The salt width in bytes, as declared by the group.
    pub fn salt_bytes(&self) -> usize {
        G::SALT_BYTES
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
        let salt: Vec<u8> = rng().random_iter().take(G::SALT_BYTES).collect();
        self.generate_new_user_secrets_with_salt(username, password, Salt::from(salt))
    }

    fn generate_new_user_secrets_with_salt(
        &self,
        username: &Username,
        password: ClearTextPasswordRef,
        salt: Salt,
    ) -> (Salt, Verifier<G>) {
        let x = steps::private_key_x(&self.group, username, password, &salt);
        let verifier = self.group.field_pow(&self.group.generator(), &x);

        (salt, Verifier::from_field(&self.group, &verifier))
    }

    #[cfg(test)]
    pub(crate) fn generate_new_user_secrets_with_fixed_salt(
        &self,
        username: &Username,
        password: ClearTextPasswordRef,
        salt: Salt,
    ) -> (Salt, Verifier<G>) {
        self.generate_new_user_secrets_with_salt(username, password, salt)
    }

    /// Starts the handshake for an existing user.
    pub fn start_handshake(
        &self,
        username: &Username,
        salt: Salt,
        verifier: Verifier<G>,
    ) -> (Handshake<G>, HandshakeProofVerifier<G>) {
        let b = self.group.random_exponent();
        self.start_handshake_with_b(username, salt, verifier, b)
    }

    fn start_handshake_with_b(
        &self,
        username: &Username,
        salt: Salt,
        verifier: Verifier<G>,
        b: G::Exponent,
    ) -> (Handshake<G>, HandshakeProofVerifier<G>) {
        let verifier_field = verifier.to_field(&self.group);
        let g = self.group.generator();
        let k = self.group.multiplier();
        let g_b = self.group.field_pow(&g, &b);
        let k_v = self.group.field_mul(&k, &verifier_field);
        let b_pub = self.group.field_add(&k_v, &g_b);

        let handshake = Handshake {
            B: PublicKey::from_field(&self.group, &b_pub),
            g: FieldElement::from_field(&self.group, &g),
            k: FieldElement::from_field(&self.group, &k),
            s: salt.clone(),
        };
        let verifier = HandshakeProofVerifier {
            b,
            B: PublicKey::from_field(&self.group, &b_pub),
            g: FieldElement::from_field(&self.group, &g),
            user: UserSecrets {
                username: username.clone(),
                salt,
                verifier,
            },
        };

        (handshake, verifier)
    }

    #[cfg(test)]
    pub(crate) fn start_handshake_with_fixed_b(
        &self,
        username: &Username,
        salt: Salt,
        verifier: Verifier<G>,
        b: G::Exponent,
    ) -> (Handshake<G>, HandshakeProofVerifier<G>) {
        self.start_handshake_with_b(username, salt, verifier, b)
    }

    /// Verifies the client's proof and returns the strong proof `M2`.
    pub fn verify_proof(
        &self,
        verifier: &HandshakeProofVerifier<G>,
        proof: &HandshakeProof<G>,
    ) -> Result<Proof> {
        let a_field = proof.A.to_field(&self.group);
        let verifier_field = verifier.user.verifier.to_field(&self.group);

        let u = steps::scrambler_u(&self.group, &proof.A, &verifier.B);
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
            return Err(Srp6Error::InvalidProof(m1));
        }

        Ok(steps::proof_m2(&proof.A, &m1, &k))
    }

    /// Calculates the client's proof and its strong-proof verifier.
    pub fn calculate_proof(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: &str,
    ) -> Result<(HandshakeProof<G>, StrongProofVerifier<G>)> {
        let a_exp = self.group.random_exponent();
        self.calculate_proof_with_a(handshake, username, password, a_exp)
    }

    fn calculate_proof_with_a(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: &str,
        a_exp: G::Exponent,
    ) -> Result<(HandshakeProof<G>, StrongProofVerifier<G>)> {
        let b_field = handshake.B.to_field(&self.group);
        let g_field = handshake.g.to_field(&self.group);
        let k_field = handshake.k.to_field(&self.group);

        let a_field = self.group.field_pow(&self.group.generator(), &a_exp);
        let a_public = PublicKey::from_field(&self.group, &a_field);

        let u = steps::scrambler_u(&self.group, &a_public, &handshake.B);
        let x = steps::private_key_x(&self.group, username, password, &handshake.s);
        let ux = self.group.exponent_mul(&u, &x);
        let exp = self.group.exponent_add(&a_exp, &ux);

        let g_x = self.group.field_pow(&g_field, &x);
        let k_gx = self.group.field_mul(&k_field, &g_x);
        let base = self.group.field_sub(&b_field, &k_gx);
        let s = self.group.field_pow(&base, &exp);
        let s = FieldElement::from_field(&self.group, &s);
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

    #[cfg(test)]
    pub(crate) fn calculate_proof_with_fixed_a(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: &str,
        a: G::Exponent,
    ) -> Result<(HandshakeProof<G>, StrongProofVerifier<G>)> {
        self.calculate_proof_with_a(handshake, username, password, a)
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
