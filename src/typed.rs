//! The typed SRP6 handshake over the closed groups.
//!
//! The boundary is byte-oriented: [`Salt`], [`FieldElement`] (with its
//! [`Verifier`] and [`PublicKey`] names) and [`Proof`] are the only numeric
//! values a caller handles. The group arithmetic and its backend stay inside
//! this module, so no crypto-bigint type reaches the public API.

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;

use rand::{rng, RngExt};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::big_number::{BigNumber, ConstantTimeEq};
use crate::credentials::{ClearTextPasswordRef, Username};
use crate::group::{Group, GroupOps};
use crate::hash::HASH_LENGTH;
use crate::primitives::{
    calculate_private_key_x, calculate_proof_M_len, calculate_session_key_hash_interleave_K_len,
    calculate_strong_proof_M2_len, calculate_u_len, PublicKey as BigPublicKey, RawPublicKey,
};
use crate::{error::Srp6Error, Result};

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02X}")?;
    }
    Ok(())
}

/// Creates a boundary value from the hex form its `Display` prints.
pub trait FromHexString: Sized {
    /// Decodes `hex`; ASCII whitespace between the digits is ignored.
    fn try_from_hex(hex: &str) -> Result<Self>;
}

/// Decodes base-16 into bytes, preserving leading zero bytes. ASCII
/// whitespace, including `\n` and `\r`, is stripped first.
fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let compact: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();

    // Reject non-ASCII before slicing: byte indexing into a multibyte char
    // would panic instead of reporting bad hex.
    if !compact.is_ascii() || !compact.len().is_multiple_of(2) {
        return Err(Srp6Error::InvalidHexString);
    }

    let mut bytes = Vec::with_capacity(compact.len() / 2);
    for i in (0..compact.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&compact[i..i + 2], 16).map_err(|_| Srp6Error::InvalidHexString)?;
        bytes.push(byte);
    }

    Ok(bytes)
}

/// A salt, as generated, stored and sent to the client.
///
/// Any byte string is a valid salt; [`Group::SALT_BYTES`] only fixes what
/// [`Srp6::generate_new_user_secrets`] draws.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt(Box<[u8]>);

impl Salt {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into().into_boxed_slice())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<Vec<u8>> for Salt {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for Salt {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl From<Salt> for Vec<u8> {
    fn from(salt: Salt) -> Self {
        salt.to_vec()
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt({self})")
    }
}

impl Serialize for Salt {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl FromHexString for Salt {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::from(decode_hex(hex)?))
    }
}

impl<'de> Deserialize<'de> for Salt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self::from(bytes))
    }
}

/// A validated field element of group `G`, in canonical fixed-width bytes.
///
/// Construction decodes the bytes as a non-zero element modulo `N`; a value of
/// this type is therefore always a valid group element, and there is no way to
/// hold a degenerate one.
///
/// [`Verifier`] and [`PublicKey`] are the semantic names used in the handshake;
/// both carry this same validation.
pub struct FieldElement<G: Group> {
    bytes: Box<[u8]>,
    _group: PhantomData<G>,
}

/// The server-stored password verifier `v`.
pub type Verifier<G> = FieldElement<G>;

/// A peer's public key `A` or `B`.
pub type PublicKey<G> = FieldElement<G>;

impl<G: Group> FieldElement<G> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl<G: GroupOps> FieldElement<G> {
    /// Decodes `bytes`, rejecting values wider than `N` or `0 mod N`.
    ///
    /// Shorter inputs are zero-padded to the group's fixed width, so
    /// [`FieldElement::to_bytes`] always returns `N_BYTES` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let group = G::default();
        let field = group
            .field_from_bytes(bytes)
            .ok_or(Srp6Error::InvalidFieldElement)?;

        Ok(Self::from_field(&group, &field))
    }

    pub(crate) fn from_field(group: &G, value: &G::Field) -> Self {
        Self {
            bytes: group.field_to_bytes(value).into_boxed_slice(),
            _group: PhantomData,
        }
    }

    pub(crate) fn to_field(&self, group: &G) -> G::Field {
        group
            .field_from_bytes(&self.bytes)
            .expect("the bytes were validated when the value was built")
    }
}

impl<G: Group> Clone for FieldElement<G> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _group: PhantomData,
        }
    }
}

impl<G: Group> PartialEq for FieldElement<G> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<G: Group> Eq for FieldElement<G> {}

impl<G: Group> AsRef<[u8]> for FieldElement<G> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<G: Group> From<FieldElement<G>> for Vec<u8> {
    fn from(value: FieldElement<G>) -> Self {
        value.to_bytes()
    }
}

impl<G: GroupOps> TryFrom<Vec<u8>> for FieldElement<G> {
    type Error = Srp6Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes(&bytes)
    }
}

impl<G: GroupOps> TryFrom<&[u8]> for FieldElement<G> {
    type Error = Srp6Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl<G: GroupOps> FromHexString for FieldElement<G> {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(&decode_hex(hex)?)
    }
}

impl<G: Group> fmt::Display for FieldElement<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.bytes)
    }
}

impl<G: Group> fmt::Debug for FieldElement<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement({self})")
    }
}

impl<G: Group> Serialize for FieldElement<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de, G: GroupOps> Deserialize<'de> for FieldElement<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// An `M1` or `M2` proof: exactly one hash-length byte string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof([u8; HASH_LENGTH]);

impl Proof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; HASH_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| Srp6Error::InvalidProofLength {
                    given: bytes.len(),
                    expected: HASH_LENGTH,
                })?;

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LENGTH] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Constant-time equality, for comparing a received proof with an expected one.
    pub fn ct_eq(&self, other: &Self) -> bool {
        BigNumber::from_bytes_be(&self.0).ct_eq(&BigNumber::from_bytes_be(&other.0))
    }

    pub(crate) fn from_big_number(value: &BigNumber) -> Self {
        let padded = value.to_array_pad_zero_len(HASH_LENGTH);
        Self::from_bytes(&padded).expect("a hash is at most HASH_LENGTH bytes")
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Proof({self})")
    }
}

impl Serialize for Proof {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl FromHexString for Proof {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(&decode_hex(hex)?)
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// The server's stored view of one user.
pub struct UserSecrets<G: Group> {
    pub username: Username,
    pub salt: Salt,
    pub verifier: Verifier<G>,
}

/// The server's opening handshake.
#[allow(non_snake_case)]
pub struct Handshake<G: Group> {
    pub B: PublicKey<G>,
    pub g: FieldElement<G>,
    pub k: FieldElement<G>,
    pub s: Salt,
}

/// What the server keeps to verify the client's proof.
#[allow(non_snake_case)]
pub struct HandshakeProofVerifier<G: GroupOps> {
    b: G::Exponent,
    pub B: PublicKey<G>,
    pub g: FieldElement<G>,
    pub user: UserSecrets<G>,
}

/// The client's proof.
#[allow(non_snake_case)]
pub struct HandshakeProof<G: Group> {
    pub A: PublicKey<G>,
    pub M1: Proof,
}

/// What the client keeps to verify the server's strong proof.
#[allow(non_snake_case)]
pub struct StrongProofVerifier<G: Group> {
    pub A: PublicKey<G>,
    pub K: BigNumber,
    pub M1: Proof,
}

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
        let x = self.group.exponent_from_hash(&x);
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
        let a =
            BigPublicKey::new(BigNumber::from_bytes_be(proof.A.as_bytes()), &n).map_err(|_| {
                Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(proof.A.as_bytes()))
            })?;
        let b_bytes = verifier.B.to_bytes();
        let b = BigPublicKey::new(BigNumber::from_bytes_be(&b_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&b_bytes)))?;

        let u = calculate_u_len(&a, &b, G::N_BYTES);
        let u = self.group.exponent_from_hash(&u);
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
            return Err(Srp6Error::InvalidProof(m1));
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
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&a_bytes)))?;
        let b_key = BigPublicKey::new(BigNumber::from_bytes_be(&b_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&b_bytes)))?;

        let u = calculate_u_len(&a_key, &b_key, G::N_BYTES);
        let u = self.group.exponent_from_hash(&u);
        let x = calculate_private_key_x(
            username,
            password,
            &BigNumber::from_bytes_be(handshake.s.as_bytes()),
        );
        let x = self.group.exponent_from_hash(&x);
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
            K: k,
            M1: Proof::from_big_number(&m1),
        };

        Ok((proof, verifier))
    }

    /// Verifies the server's strong proof.
    pub fn verify_strong_proof(
        &self,
        verifier: &StrongProofVerifier<G>,
        m2: &Proof,
    ) -> Result<BigNumber> {
        let a_bytes = verifier.A.to_bytes();
        let n = BigNumber::from_bytes_be(&self.group.modulus_bytes());
        let a = BigPublicKey::new(BigNumber::from_bytes_be(&a_bytes), &n)
            .map_err(|_| Srp6Error::InvalidPublicKey(RawPublicKey::from_bytes_be(&a_bytes)))?;

        let m1 = BigNumber::from_bytes_be(verifier.M1.as_bytes());
        let expected = Proof::from_big_number(&calculate_strong_proof_M2_len(
            &a,
            &m1,
            &verifier.K,
            G::N_BYTES,
        ));
        if !expected.ct_eq(m2) {
            return Err(Srp6Error::InvalidStrongProof(BigNumber::from_bytes_be(
                m2.as_bytes(),
            )));
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

    fn round_trip<G: GroupOps>(group: G) {
        let srp = Srp6::new(group);
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
        let srp = Srp6::new(Group2048);
        let username = Username::new("alice").expect("valid username");
        let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");
        let (handshake, proof_verifier) = srp.start_handshake(&username, salt, verifier);
        let (proof, _) = srp
            .calculate_proof(&handshake, &username, "wrong")
            .expect("the client can prove");
        assert!(srp.verify_proof(&proof_verifier, &proof).is_err());
    }

    #[test]
    fn a_verifier_round_trips_through_its_bytes() {
        let srp = Srp6::new(Group2048);
        let username = Username::new("alice").expect("valid username");
        let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");

        let salt = Salt::from(salt.to_vec());
        let verifier = Verifier::<Group2048>::from_bytes(&verifier.to_bytes())
            .expect("the verifier is a field element");
        srp.start_handshake(&username, salt, verifier);
    }

    #[test]
    fn degenerate_values_are_refused() {
        assert!(Verifier::<Group2048>::from_bytes(&[0_u8; 256]).is_err());
        assert!(Verifier::<Group2048>::from_bytes(&[0_u8; 257]).is_err());
        assert!(Proof::from_bytes(&[0_u8; HASH_LENGTH - 1]).is_err());
    }

    #[test]
    fn hex_round_trips_through_the_boundary_types() {
        let srp = Srp6::new(Group2048);
        let username = Username::new("alice").expect("valid username");
        let (salt, verifier) = srp.generate_new_user_secrets(&username, "password123");

        let salt = Salt::try_from_hex(&salt.to_string()).expect("the salt hex decodes");
        let verifier = Verifier::<Group2048>::try_from_hex(&verifier.to_string())
            .expect("the verifier hex decodes");
        srp.start_handshake(&username, salt, verifier);
    }

    #[test]
    fn hex_decoding_preserves_leading_zero_bytes() {
        let salt = Salt::try_from_hex("00ab").expect("valid hex");
        assert_eq!(salt.as_bytes(), &[0x00, 0xAB]);
        assert_eq!(salt.to_string(), "00AB");
    }

    #[test]
    fn hex_decoding_strips_whitespace_between_octlets() {
        let contiguous = Salt::try_from_hex("00ABCDEF").expect("valid hex");

        assert_eq!(
            contiguous,
            Salt::try_from_hex("00 AB CD EF").expect("spaces between octlets")
        );
        assert_eq!(
            contiguous,
            Salt::try_from_hex("\r\n00\tAB\r\nCD EF\n").expect("CRLF and tabs")
        );
    }

    #[test]
    fn invalid_hex_is_refused() {
        assert!(Salt::try_from_hex("ABC").is_err());
        assert!(Salt::try_from_hex("zz").is_err());
        assert!(Salt::try_from_hex("é0").is_err());
        assert!(Proof::try_from_hex("00").is_err());
        assert!(Verifier::<Group2048>::try_from_hex("00").is_err());
    }
}
