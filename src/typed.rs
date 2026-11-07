//! The typed SRP6 handshake over the closed groups.
//!
//! The wire types stay byte-oriented; this module keeps the arithmetic in each
//! group's Montgomery field and converts only where a hash or the wire needs
//! bytes.

use std::marker::PhantomData;

use rand::{rng, RngExt};

use crate::big_number::ConstantTimeEq;
use crate::group::Group;
use crate::prelude::*;
use crate::primitives::{
    calculate_private_key_x, calculate_proof_M_len, calculate_session_key_hash_interleave_K_len,
    calculate_strong_proof_M2_len, calculate_u_len,
};
use crate::{error::Srp6Error, Result};

/// The server's stored view of one user.
pub struct TypedUserSecrets<G: Group> {
    pub username: Username,
    pub salt: Vec<u8>,
    pub verifier: G::Field,
}

/// The server's opening handshake.
#[allow(non_snake_case)]
pub struct TypedHandshake<G: Group> {
    pub B: G::Field,
    pub g: G::Field,
    pub k: G::Field,
    pub s: Vec<u8>,
}

/// What the server keeps to verify the client's proof.
#[allow(non_snake_case)]
pub struct TypedProofVerifier<G: Group> {
    pub b: G::Exponent,
    pub B: G::Field,
    pub g: G::Field,
    pub user: TypedUserSecrets<G>,
}

/// The client's proof.
#[allow(non_snake_case)]
pub struct TypedProof<G: Group> {
    pub A: Vec<u8>,
    pub M1: BigNumber,
    _group: PhantomData<G>,
}

/// What the client keeps to verify the server's strong proof.
#[allow(non_snake_case)]
pub struct TypedStrongProofVerifier<G: Group> {
    pub A: G::Field,
    pub K: BigNumber,
    pub M1: BigNumber,
}

/// The SRP6 handshake for one closed group.
pub struct TypedSrp6<G: Group> {
    pub group: G,
}

impl<G: Group> TypedSrp6<G> {
    pub fn new(group: G) -> Self {
        Self { group }
    }

    /// Creates a salt and password verifier for a new user.
    pub fn generate_new_user_secrets(
        &self,
        username: &Username,
        password: &str,
    ) -> (Vec<u8>, G::Field) {
        let salt: Vec<u8> = rng().random_iter().take(G::SALT_BYTES).collect();
        let x = calculate_private_key_x(username, password, &BigNumber::from_bytes_be(&salt));
        let x = self.group.exponent_from_hash(&x);
        let verifier = self.group.field_pow(&self.group.generator(), &x);

        (salt, verifier)
    }

    /// Starts the handshake for an existing user.
    pub fn start_handshake(
        &self,
        username: &Username,
        salt: Vec<u8>,
        verifier: G::Field,
    ) -> (TypedHandshake<G>, TypedProofVerifier<G>) {
        let b = self.group.random_exponent();
        let g = self.group.generator();
        let k = self.group.multiplier();
        let g_b = self.group.field_pow(&g, &b);
        let k_v = self.group.field_mul(&k, &verifier);
        let b_pub = self.group.field_add(&k_v, &g_b);

        let handshake = TypedHandshake {
            B: b_pub.clone(),
            g: g.clone(),
            k,
            s: salt.clone(),
        };
        let verifier = TypedProofVerifier {
            b,
            B: b_pub,
            g,
            user: TypedUserSecrets {
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
        verifier: &TypedProofVerifier<G>,
        proof: &TypedProof<G>,
    ) -> Result<BigNumber> {
        let a_field = self
            .group
            .field_from_bytes(&proof.A)
            .ok_or_else(|| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&proof.A)))?;

        let n = BigNumber::from_bytes_be(&self.group.modulus_bytes());
        let a = PublicKey::new(BigNumber::from_bytes_be(&proof.A), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&proof.A)))?;
        let b_bytes = self.group.field_to_bytes(&verifier.B);
        let b = PublicKey::new(BigNumber::from_bytes_be(&b_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&b_bytes)))?;

        let u = calculate_u_len(&a, &b, G::N_BYTES);
        let u = self.group.exponent_from_hash(&u);
        let v_u = self.group.field_pow(&verifier.user.verifier, &u);
        let a_vu = self.group.field_mul(&a_field, &v_u);
        let s = self.group.field_pow(&a_vu, &verifier.b);
        let k = calculate_session_key_hash_interleave_K_len(
            &BigNumber::from_bytes_be(&self.group.field_to_bytes(&s)),
            G::N_BYTES,
        );

        let salt = Salt::from_bytes_be(&verifier.user.salt);
        let g = BigNumber::from_bytes_be(&self.group.field_to_bytes(&verifier.g));
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
        if !m1.ct_eq(&proof.M1) {
            return Err(Srp6Error::InvalidProof(m1));
        }

        Ok(calculate_strong_proof_M2_len(&a, &m1, &k, G::N_BYTES))
    }

    /// Calculates the client's proof and its strong-proof verifier.
    pub fn calculate_proof(
        &self,
        handshake: &TypedHandshake<G>,
        username: &Username,
        password: &str,
    ) -> Result<(TypedProof<G>, TypedStrongProofVerifier<G>)> {
        let a_exp = self.group.random_exponent();
        let a = self.group.field_pow(&self.group.generator(), &a_exp);
        let a_bytes = self.group.field_to_bytes(&a);
        let b_bytes = self.group.field_to_bytes(&handshake.B);

        let n = BigNumber::from_bytes_be(&self.group.modulus_bytes());
        let a_key = PublicKey::new(BigNumber::from_bytes_be(&a_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&a_bytes)))?;
        let b_key = PublicKey::new(BigNumber::from_bytes_be(&b_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&b_bytes)))?;

        let u = calculate_u_len(&a_key, &b_key, G::N_BYTES);
        let u = self.group.exponent_from_hash(&u);
        let x = calculate_private_key_x(username, password, &Salt::from_bytes_be(&handshake.s));
        let x = self.group.exponent_from_hash(&x);
        let ux = self.group.exponent_mul(&u, &x);
        let exp = self.group.exponent_add(&a_exp, &ux);

        let g_x = self.group.field_pow(&handshake.g, &x);
        let k_gx = self.group.field_mul(&handshake.k, &g_x);
        let base = self.group.field_sub(&handshake.B, &k_gx);
        let s = self.group.field_pow(&base, &exp);
        let k = calculate_session_key_hash_interleave_K_len(
            &BigNumber::from_bytes_be(&self.group.field_to_bytes(&s)),
            G::N_BYTES,
        );

        let salt = Salt::from_bytes_be(&handshake.s);
        let g = BigNumber::from_bytes_be(&self.group.field_to_bytes(&handshake.g));
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

        let proof = TypedProof {
            A: a_bytes,
            M1: m1.clone(),
            _group: PhantomData,
        };
        let verifier = TypedStrongProofVerifier { A: a, K: k, M1: m1 };

        Ok((proof, verifier))
    }

    /// Verifies the server's strong proof.
    pub fn verify_strong_proof(
        &self,
        verifier: &TypedStrongProofVerifier<G>,
        m2: &BigNumber,
    ) -> Result<BigNumber> {
        let a_bytes = self.group.field_to_bytes(&verifier.A);
        let n = BigNumber::from_bytes_be(&self.group.modulus_bytes());
        let a = PublicKey::new(BigNumber::from_bytes_be(&a_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&a_bytes)))?;

        let expected = calculate_strong_proof_M2_len(&a, &verifier.M1, &verifier.K, G::N_BYTES);
        if !expected.ct_eq(m2) {
            return Err(Srp6Error::InvalidStrongProof(m2.clone()));
        }

        Ok(verifier.K.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{Group2048, Group4096};

    #[cfg(feature = "wow-1-12-1")]
    use crate::group::GroupWow;

    fn round_trip<G: Group>(group: G) {
        let srp = TypedSrp6::new(group);
        let username = Username::new("alice").expect("valid username");
        let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
        let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
        let (proof, strong_verifier) = srp
            .calculate_proof(&handshake, &username, "password123")
            .expect("the client can prove");
        let m2 = srp
            .verify_proof(&proof_verifier, &proof)
            .expect("the proof verifies");
        srp.verify_strong_proof(&strong_verifier, &m2)
            .expect("the strong proof verifies");
    }

    #[test]
    fn a_2048_bit_handshake_round_trips() {
        round_trip(Group2048);
    }

    #[test]
    fn a_4096_bit_handshake_round_trips() {
        round_trip(Group4096);
    }

    #[cfg(feature = "wow-1-12-1")]
    #[test]
    fn a_wow_handshake_round_trips() {
        round_trip(GroupWow);
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let srp = TypedSrp6::new(Group2048);
        let username = Username::new("alice").expect("valid username");
        let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
        let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
        let (proof, _) = srp
            .calculate_proof(&handshake, &username, "wrong")
            .expect("the client can prove");
        assert!(srp.verify_proof(&proof_verifier, &proof).is_err());
    }
}
