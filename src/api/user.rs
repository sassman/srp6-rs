use serde::{Deserialize, Serialize};

use super::host::Handshake;
use crate::primitives::*;
use crate::{Result, Srp6Error};

/// Contains the client's [`PublicKey`] and their [`Proof`] and is sent to the server
#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct HandshakeProof<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {
    /// the client public key
    pub A: PublicKey,
    /// the clients proof
    pub M1: Proof,
}

/// Verifies the [`StrongProof`] provided by the server to the client
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct StrongProofVerifier<const KEY_LENGTH: usize> {
    pub A: PublicKey,
    pub K: StrongSessionKey,
    pub M1: Proof,
}

impl<const KEY_LENGTH: usize> StrongProofVerifier<KEY_LENGTH> {
    /// verifies a [`StrongProof`] from the server on the client side
    #[allow(non_snake_case)]
    pub fn verify_strong_proof(&self, M2: &StrongProof) -> Result<StrongSessionKey> {
        let A = &self.A;
        let M = &self.M1;
        let K = &self.K;
        let my_strong_proof = calculate_strong_proof_M2::<KEY_LENGTH>(A, M, K);

        if M2 != &my_strong_proof {
            Err(Srp6Error::InvalidStrongProof(M2.clone()))
        } else {
            Ok(K.clone())
        }
    }
}

/// Calculates client [`Proof`] `M1` with a more high level api
#[allow(non_snake_case)]
pub(crate) fn calculate_proof_M_for_client<const KL: usize, const SL: usize>(
    handshake: &Handshake<KL, SL>,
    credentials: &UserCredentials,
) -> Result<(HandshakeProof<KL, SL>, StrongProofVerifier<KL>)> {
    let username = credentials.username;
    let user_password = credentials.password;
    let a = generate_private_key::<KL>();
    let A = calculate_pubkey_A(&handshake.N, &handshake.g, &a);
    let x = calculate_private_key_x(username, user_password, &handshake.s);
    let S = calculate_session_key_S_for_client::<KL>(
        &handshake.N,
        &handshake.k,
        &handshake.g,
        &handshake.B,
        &A,
        &a,
        &x,
    )?;
    let K = calculate_session_key_hash_interleave_K::<KL>(&S);
    let M1 = calculate_proof_M::<KL, SL>(
        &handshake.N,
        &handshake.g,
        username,
        &handshake.s,
        &A,
        &handshake.B,
        &K,
    );

    let strong_proof_verifier = StrongProofVerifier {
        A: A.clone(),
        K,
        M1: M1.clone(),
    };
    let proof = HandshakeProof { A, M1 };

    Ok((proof, strong_proof_verifier))
}
