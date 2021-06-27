use crate::api::host::{Handshake, HandshakeProof};
use crate::primitives::*;
use crate::Result;

/// calculates client [`Proof`] `M1` with a more high level api
#[allow(non_snake_case)]
pub fn calculate_proof_M_for_client<const KL: usize, const SL: usize>(
    handshake: &Handshake<KL, SL>,
    credentials: &UserCredentials,
) -> Result<HandshakeProof<KL, SL>> {
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

    Ok(HandshakeProof { A, M1 })
}
