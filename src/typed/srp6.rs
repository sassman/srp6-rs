use rand::{rng, RngExt};

use super::{
    FieldElement, Handshake, HandshakeProof, HandshakeProofVerifier, Proof, PublicKey, Salt,
    StrongProofVerifier, StrongSessionKey, UserSecrets, Verifier,
};
use crate::big_number::BigNumber;
use crate::credentials::{ClearTextPasswordRef, Username};
use crate::group::{Group, GroupOps};
use crate::primitives::{
    calculate_private_key_x, calculate_proof_M_len, calculate_session_key_hash_interleave_K_len,
    calculate_strong_proof_M2_len, calculate_u_len, PublicKey as BigPublicKey,
};
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
        let x = calculate_private_key_x(username, password, &BigNumber::from_bytes_be(&salt));
        let x = self.group.exponent_from_hash(&x.to_vec());
        let verifier = self.group.field_pow(&self.group.generator(), &x);

        (
            Salt::from(salt),
            Verifier::from_field(&self.group, &verifier),
        )
    }

    /// Starts the handshake for an existing user.
    pub fn start_handshake(
        &self,
        username: &Username,
        salt: Salt,
        verifier: Verifier<G>,
    ) -> (Handshake<G>, HandshakeProofVerifier<G>) {
        let verifier_field = verifier.to_field(&self.group);
        let b = self.group.random_exponent();
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

    /// Verifies the client's proof and returns the strong proof `M2`.
    pub fn verify_proof(
        &self,
        verifier: &HandshakeProofVerifier<G>,
        proof: &HandshakeProof<G>,
    ) -> Result<Proof> {
        let a_field = proof.A.to_field(&self.group);

        let n = BigNumber::from_bytes_be(&self.group.modulus_bytes());
        let a = BigPublicKey::new(BigNumber::from_bytes_be(proof.A.as_bytes()), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(proof.A.as_bytes().to_vec()))?;
        let b_bytes = verifier.B.to_bytes();
        let b = BigPublicKey::new(BigNumber::from_bytes_be(&b_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(b_bytes))?;

        let u = calculate_u_len(&a, &b, G::N_BYTES);
        let u = self.group.exponent_from_hash(&u.to_vec());
        let verifier_field = verifier.user.verifier.to_field(&self.group);
        let v_u = self.group.field_pow(&verifier_field, &u);
        let a_vu = self.group.field_mul(&a_field, &v_u);
        let s = self.group.field_pow(&a_vu, &verifier.b);
        let k = calculate_session_key_hash_interleave_K_len(
            &BigNumber::from_bytes_be(&self.group.field_to_bytes(&s)),
            G::N_BYTES,
        );

        let salt = BigNumber::from_bytes_be(verifier.user.salt.as_bytes());
        let g = BigNumber::from_bytes_be(&verifier.g.to_bytes());
        let m1 = calculate_proof_M_len(
            &n,
            &g,
            &verifier.user.username,
            &salt,
            &a,
            &b,
            &k,
            G::N_BYTES,
            G::SALT_BYTES,
        );
        if !Proof::from_big_number(&m1).ct_eq(&proof.M1) {
            return Err(Srp6Error::InvalidProof(Proof::from_big_number(&m1)));
        }

        Ok(Proof::from_big_number(&calculate_strong_proof_M2_len(
            &a,
            &m1,
            &k,
            G::N_BYTES,
        )))
    }

    /// Calculates the client's proof and its strong-proof verifier.
    pub fn calculate_proof(
        &self,
        handshake: &Handshake<G>,
        username: &Username,
        password: &str,
    ) -> Result<(HandshakeProof<G>, StrongProofVerifier<G>)> {
        let b_field = handshake.B.to_field(&self.group);
        let g_field = handshake.g.to_field(&self.group);
        let k_field = handshake.k.to_field(&self.group);

        let a_exp = self.group.random_exponent();
        let a = self.group.field_pow(&self.group.generator(), &a_exp);
        let a_bytes = self.group.field_to_bytes(&a);
        let b_bytes = self.group.field_to_bytes(&b_field);

        let n = BigNumber::from_bytes_be(&self.group.modulus_bytes());
        let a_key = BigPublicKey::new(BigNumber::from_bytes_be(&a_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(a_bytes))?;
        let b_key = BigPublicKey::new(BigNumber::from_bytes_be(&b_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(b_bytes))?;

        let u = calculate_u_len(&a_key, &b_key, G::N_BYTES);
        let u = self.group.exponent_from_hash(&u.to_vec());
        let x = calculate_private_key_x(
            username,
            password,
            &BigNumber::from_bytes_be(handshake.s.as_bytes()),
        );
        let x = self.group.exponent_from_hash(&x.to_vec());
        let ux = self.group.exponent_mul(&u, &x);
        let exp = self.group.exponent_add(&a_exp, &ux);

        let g_x = self.group.field_pow(&g_field, &x);
        let k_gx = self.group.field_mul(&k_field, &g_x);
        let base = self.group.field_sub(&b_field, &k_gx);
        let s = self.group.field_pow(&base, &exp);
        let k = calculate_session_key_hash_interleave_K_len(
            &BigNumber::from_bytes_be(&self.group.field_to_bytes(&s)),
            G::N_BYTES,
        );

        let salt = BigNumber::from_bytes_be(handshake.s.as_bytes());
        let g = BigNumber::from_bytes_be(&handshake.g.to_bytes());
        let m1 = calculate_proof_M_len(
            &n,
            &g,
            username,
            &salt,
            &a_key,
            &b_key,
            &k,
            G::N_BYTES,
            G::SALT_BYTES,
        );

        let a_public = PublicKey::from_field(&self.group, &a);
        let proof = HandshakeProof {
            A: a_public.clone(),
            M1: Proof::from_big_number(&m1),
        };
        let verifier = StrongProofVerifier {
            A: a_public,
            K: StrongSessionKey::from_big_number(&k),
            M1: Proof::from_big_number(&m1),
        };

        Ok((proof, verifier))
    }

    /// Verifies the server's strong proof.
    pub fn verify_strong_proof(
        &self,
        verifier: &StrongProofVerifier<G>,
        m2: &Proof,
    ) -> Result<StrongSessionKey> {
        let a_bytes = verifier.A.to_bytes();
        let n = BigNumber::from_bytes_be(&self.group.modulus_bytes());
        let a = BigPublicKey::new(BigNumber::from_bytes_be(&a_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(a_bytes))?;

        let k = BigNumber::from_bytes_be(verifier.K.as_bytes());
        let m1 = BigNumber::from_bytes_be(verifier.M1.as_bytes());
        let expected =
            Proof::from_big_number(&calculate_strong_proof_M2_len(&a, &m1, &k, G::N_BYTES));
        if !expected.ct_eq(m2) {
            return Err(Srp6Error::InvalidStrongProof(*m2));
        }

        Ok(verifier.K)
    }
}
