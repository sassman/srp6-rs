use crate::prelude::*;
use crate::Result;
use serde::{Deserialize, Serialize};

/// this trait provides a higher level api
pub trait HostAPI<const KL: usize, const SL: usize> {
    /// For new users, or if they recover their password
    #[allow(non_snake_case)]
    fn generate_new_user_secrets(
        &self,
        I: UsernameRef,
        p: ClearTextPasswordRef,
    ) -> (Salt, PasswordVerifier);

    /// For new users, or if they recover their password
    /// For tests only
    #[cfg(test)]
    #[allow(non_snake_case)]
    fn generate_new_user_secrets_w_salt(
        &self,
        I: UsernameRef,
        p: ClearTextPasswordRef,
        s: Salt,
    ) -> (Salt, PasswordVerifier);

    /// starts the handshake with the client
    fn start_handshake(&self, user: &UserSecrets) -> (Handshake<KL, SL>, HandshakeProofVerifier);
}

/// Contains all variables needed for a successful
/// session key generation provided by the server to the client
#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Handshake<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {
    /// the servers public key
    pub B: PublicKey,
    /// a generator modulo N
    pub g: Generator,
    /// a big and safe prime number
    pub N: PrimeModulus,
    /// multiplier parameter
    pub k: MultiplierParameter,
    /// the users salt
    pub s: Salt,
}

/// This is responsible for verifying a [`HandshakeProof`] that is
/// provided by the client to the server
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct HandshakeProofVerifier {
    /// the servers pub and private key
    pub server_keys: KeyPair,
    /// the users s, v and I
    pub user: UserSecrets,
    /// a generator modulo N
    pub g: Generator,
    /// a big and safe prime number
    pub N: PrimeModulus,
}

impl HandshakeProofVerifier {
    /// verifies a proof provided by the client
    #[allow(non_snake_case)]
    pub fn verify_proof<const N_BYTE_LEN: usize, const SALT_LENGTH: usize>(
        &self,
        proof: &HandshakeProof<N_BYTE_LEN, SALT_LENGTH>,
    ) -> Result<(StrongProof, StrongSessionKey)> {
        let (B, b) = &self.server_keys;
        let N = &self.N;
        let g = &self.g;
        let I = &self.user.username;
        let s = &self.user.salt;
        let v = &self.user.verifier;
        let A = &proof.A;
        let M1 = &proof.M1;

        let S = &calculate_session_key_S_for_host::<N_BYTE_LEN>(N, A, B, b, v)?;
        let K = calculate_session_key_hash_interleave_K::<N_BYTE_LEN>(S);
        let M = &calculate_proof_M::<N_BYTE_LEN, SALT_LENGTH>(N, g, I, s, A, B, &K);

        if M != M1 {
            return Err(Srp6Error::InvalidProof(M.clone()));
        }
        let M2 = calculate_strong_proof_M2::<N_BYTE_LEN>(A, M, &K);

        Ok((M2, K))
    }
}

/// Main interaction point for the server
#[allow(non_snake_case)]
#[derive(Debug, Serialize)]
pub struct Srp6<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {
    /// A large safe prime (N = 2q+1, where q is prime. All arithmetic is done modulo N.
    /// `KEY_LENGTH` needs to match the bytes of [`PrimeModulus`] `N`
    pub N: PrimeModulus,
    /// A generator modulo N
    pub g: Generator,
    /// multiplier parameter
    pub k: MultiplierParameter,
}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> Srp6<KEY_LENGTH, SALT_LENGTH> {
    pub const KEY_LEN: usize = KEY_LENGTH;
    pub const SALT_LEN: usize = SALT_LENGTH;

    /// this constructor takes care of calculate the right `k`
    #[allow(non_snake_case)]
    pub fn new(g: Generator, N: PrimeModulus) -> Result<Self> {
        if N.num_bytes() != KEY_LENGTH {
            return Err(Srp6Error::KeyLengthMismatch {
                expected: KEY_LENGTH,
                given: N.num_bytes(),
            });
        }
        let k = calculate_k::<KEY_LENGTH>(&N, &g);
        Ok(Self { N, g, k })
    }
}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> HostAPI<KEY_LENGTH, SALT_LENGTH>
    for Srp6<KEY_LENGTH, SALT_LENGTH>
{
    /// creates a new [`Salt`] `s` and [`PasswordVerifier`] `v` for a new user
    #[allow(non_snake_case)]
    fn generate_new_user_secrets(
        &self,
        I: UsernameRef,
        p: ClearTextPasswordRef,
    ) -> (Salt, PasswordVerifier) {
        let s = generate_salt::<SALT_LENGTH>();
        let x = calculate_private_key_x(I, p, &s);
        let v = calculate_password_verifier_v(&self.N, &self.g, &x);

        (s, v)
    }

    /// for test purposes only, we allow to inject the salt.
    /// In production salt is always random.
    #[cfg(test)]
    #[allow(non_snake_case)]
    fn generate_new_user_secrets_w_salt(
        &self,
        I: UsernameRef,
        p: ClearTextPasswordRef,
        s: Salt,
    ) -> (Salt, PasswordVerifier) {
        let x = calculate_private_key_x(I, p, &s);
        let v = calculate_password_verifier_v(&self.N, &self.g, &x);

        (s, v)
    }

    /// starts a session handshake for a given user
    /// [`Salt`] `s` and [`PasswordVerifier`] `p` are both user specific,
    /// initially they are generated by [`HostAPI::generate_new_user_secrets()`]
    #[allow(non_snake_case)]
    fn start_handshake(
        &self,
        user: &UserSecrets,
    ) -> (Handshake<KEY_LENGTH, SALT_LENGTH>, HandshakeProofVerifier) {
        let (s, v) = (&user.salt, &user.verifier);
        let b = generate_private_key::<KEY_LENGTH>();

        let B = calculate_pubkey_B(&self.N, &self.k, &self.g, v, &b);

        let h = Handshake {
            N: self.N.clone(),
            g: self.g.clone(),
            k: self.k.clone(),
            s: s.clone(),
            B: B.clone(),
        };

        let pv = HandshakeProofVerifier {
            server_keys: (B, b),
            user: user.clone(),
            g: self.g.clone(),
            N: self.N.clone(),
        };

        (h, pv)
    }
}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> Handshake<KEY_LENGTH, SALT_LENGTH> {
    /// client proof calculation
    /// User:  x = H(s, p)                 (user enters password)
    /// User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
    /// User:  K = H(S)
    pub fn calculate_proof(
        &self,
        username: UsernameRef,
        password: ClearTextPasswordRef,
    ) -> Result<(
        HandshakeProof<KEY_LENGTH, SALT_LENGTH>,
        StrongProofVerifier<KEY_LENGTH>,
    )> {
        use super::user::calculate_proof_M_for_client;

        let credentials = UserCredentials { username, password };
        calculate_proof_M_for_client::<KEY_LENGTH, SALT_LENGTH>(self, &credentials)
    }
}

#[test]
fn should_panic_when_key_length_does_not_fit_to_modulus() {
    type Srp = Srp6<10, 10>;
    let err = Srp::new(
        Generator::from(3),
        PrimeModulus::from_hex_str_be("FE27").unwrap(),
    );
    assert!(err.is_err());
    assert_eq!(
        err.err().unwrap(),
        Srp6Error::KeyLengthMismatch {
            expected: Srp::KEY_LEN,
            given: 2
        }
    )
}
