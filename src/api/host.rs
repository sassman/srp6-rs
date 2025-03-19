use super::user::{HandshakeProof, StrongProofVerifier};
use crate::primitives::*;
use crate::{Result, Srp6Error};
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::StrongSessionKey;
    use std::convert::TryInto;

    pub struct Srp6_256Mock;
    impl Srp6_256Mock {
        #[allow(non_snake_case)]
        pub fn I() -> UsernameRef<'static> {
            "ADMINISTRATOR"
        }

        pub fn p() -> ClearTextPasswordRef<'static> {
            "ADMINISTRATOR"
        }

        pub fn v() -> PasswordVerifier {
            "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18"
                .try_into()
                .unwrap()
        }
        pub fn b() -> PrivateKey {
            "ACDCB7CB1DE67DB1D5E0A37DAE80068BCCE062AE0EDA0CBEADF560BCDAE6D6B9"
                .try_into()
                .unwrap()
        }

        #[allow(non_snake_case)]
        pub fn B() -> PublicKey {
            "35A59FAEEBBE7E45204EE68B16430F9C999392DA17931148B249290FF8F5BBF6"
                .try_into()
                .unwrap()
        }

        #[allow(non_snake_case)]
        pub fn A() -> PublicKey {
            "1FFB26380AB82F00FB01A7EBC01C4967E76DC129FF35174E4C6D3C190C36D697"
                .try_into()
                .unwrap()
        }

        pub fn s() -> Salt {
            "A67FFC191C7EF028F4351E5AE7B65B817448E9F904B4DC7A6572E7F23C8558D5"
                .try_into()
                .unwrap()
        }

        #[allow(non_snake_case)]
        pub fn S() -> SessionKey {
            "1EC9B973F4EEDBA8441C0F52FEF4191154B31CAF4D6D30B1D0BABB5CD0385F67"
                .try_into()
                .unwrap()
        }

        #[allow(non_snake_case)]
        pub fn K() -> StrongSessionKey {
            "260473D7AEF9043C2E8C65C2CCF479E948D213E3CD00BC869BE64E530D4662A9A4168DDC0A834713"
                .try_into()
                .unwrap()
        }

        #[allow(non_snake_case)]
        pub fn M() -> Proof {
            "E4A1C32579947717FAD2306ED9BC7F4307E4FAFA"
                .try_into()
                .unwrap()
        }

        pub fn x() -> PrivateKey {
            "AE44391953F49241C4FA1FF6E134023397B89905"
                .try_into()
                .unwrap()
        }
    }

    pub type Mock = Srp6_256Mock;

    #[test]
    #[cfg(feature = "wow")]
    fn should_prepare_a_new_user_w_case_insensitive_username() {
        use crate::dangerous::Srp6_256;

        let (s, v) = Srp6_256::default().generate_new_user_secrets_w_salt(
            "ADMINISTRATOR",
            "administrator",
            Mock::s(),
        );
        assert_eq!(s, Mock::s(), "Salt is not correct: {}", s.to_string());
        assert_eq!(v, Mock::v(), "Verifier is not correct: {}", v.to_string());

        let (s, v) = Srp6_256::default().generate_new_user_secrets_w_salt(
            "administrator",
            "administrator",
            Mock::s(),
        );
        assert_eq!(s, Mock::s());
        assert_eq!(v, Mock::v());

        // with a random salt things are always different
        let (s, v) =
            Srp6_256::default().generate_new_user_secrets("administrator", "administrator");
        assert_ne!(s, Mock::s());
        assert_ne!(v, Mock::v());
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

    #[test]
    #[allow(non_snake_case)]
    #[cfg(feature = "wow")]
    fn should_do_the_full_round_trip_to_proof() {
        use crate::dangerous::Srp6_256;

        // hard mocked
        let user = mocked_user_details();

        // given
        let srp6 = Srp6_256::default();
        let (handshake, proof_verifier) = srp6.start_handshake(&user);

        // when
        // a client provides proof
        let user_password: ClearTextPasswordRef = Mock::p();
        let (proof, strong_proof_verifier) = handshake
            .calculate_proof(user.username.as_str(), user_password)
            .unwrap();

        // then
        // a server verifies users proof
        let strong_proof = proof_verifier.verify_proof(&proof);
        assert!(strong_proof.is_ok());
        let (strong_proof, _key) = strong_proof.unwrap();

        // also the client needs to verify
        let _session_key = strong_proof_verifier
            .verify_strong_proof(&strong_proof)
            .unwrap();
    }

    #[cfg(feature = "dangerous")]
    fn mocked_user_details() -> UserSecrets {
        UserSecrets {
            username: Mock::I().to_owned(),
            salt: Mock::s(),
            verifier: Mock::v(),
        }
    }
}
