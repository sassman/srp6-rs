# Single Type per Protocol Concept Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every SRP-6 protocol concept has exactly one type definition in the crate, and the numeric layer is deleted after its last use is ported.

**Architecture:** The byte-backed types in `src/typed/` become the only definitions. The five remaining hash steps move to typed bytes, the numeric oracle is ported to the public handshake and then deleted, and the test suite pins the shipped path. Golden vectors drive the public `Srp6` handshake through `#[cfg(test)]` deterministic entry points. No `BigNumber` or `primitives` module remains.

**Tech Stack:** Rust 2018, crypto-bigint 0.7, serde, subtle, sha1/sha2, cargo test/clippy/fmt.

---

## Context

The previous plan hid the numeric layer from the public API. It did not remove the duplicate definitions inside the crate. The current state has three kinds of duplication:

- `Salt`, `Proof`, `StrongSessionKey`, `Verifier`: a real typed type plus a `BigNumber` alias.
- `PublicKey`: a typed alias plus a real `BigNumber` newtype.
- `PrimeModulus`, `Generator`, `PrivateKey`, `PasswordVerifier`, `MultiplierParameter`, `SessionKey`: arithmetic vocabulary with no typed counterpart.

The typed driver still delegates `x`, `u`, `K`, `M1`, and `M2` to the numeric layer. That delegation is the only reason the numeric protocol names still reach production code. The golden vectors also use the numeric pipeline because the typed API generates salt and exponents internally.

The rule this plan enforces:

1. A protocol concept has one definition, in `src/typed/`.
2. The numeric layer is temporary: every production use is ported to typed bytes, then the layer is deleted.
3. Tests drive the public `Srp6` handshake through `#[cfg(test)]` deterministic entry points.
4. The final crate has no `BigNumber`, no numeric aliases, and no second representation of a protocol value.

### Numeric layer removal

The numeric aliases keep their current names only until the port is complete. No suffix rename is needed because Task 11 deletes the layer; the typed names are the only names that remain.

Task 5 is an intermediate checkpoint: it proves the production build has no numeric dependency before Task 11 deletes the layer.

### Protocol type catalogue

| Concept | Definition today | Target |
|---|---|---|
| `N` | `Group` constants + `primitives::PrimeModulus` | `Group::modulus_bytes`; numeric alias deleted |
| `g` | `Group::generator` + `FieldElement<G>` + `Generator` alias | `Group`/`FieldElement<G>`; numeric alias deleted |
| `k` | `Group::multiplier` + `FieldElement<G>` + `MultiplierParameter` alias | same; numeric alias deleted |
| `s` | `typed::Salt` + `primitives::Salt` alias | `typed::Salt`; numeric alias deleted |
| `v` | `Verifier<G>` alias + `PasswordVerifier` alias | `Verifier<G>` alias; numeric alias deleted |
| `A`, `B` | `PublicKey<G>` alias + `primitives::PublicKey(BigNumber)` | `typed::PublicKey<G>` newtype; numeric struct deleted |
| `x`, `a`, `b` | `G::Exponent` + `PrivateKey` alias | `G::Exponent`; numeric alias deleted |
| `u` | plain `BigNumber` | `G::Exponent`; no named type |
| `S` | `primitives::SessionKey` alias | `G::Field`; numeric alias deleted |
| `K` | `typed::StrongSessionKey` + alias | `typed::StrongSessionKey`; numeric alias deleted |
| `M1`, `M2` | `typed::Proof` + `Proof`/`StrongProof` aliases | `typed::Proof`; numeric aliases deleted |
| `I`, `P` | `Username`, `ClearTextPassword` | unchanged |
| Handshake messages | typed structs | unchanged |
| Driver | `Srp6<G>` | unchanged |

### Target module map

```
src/typed/
  field_element.rs      FieldElement<G>, Verifier<G> (alias)
  public_key.rs         PublicKey<G> (newtype, validated)
  salt.rs               Salt
  proof.rs              Proof (M1 and M2)
  strong_session_key.rs StrongSessionKey
  handshake.rs          UserSecrets, Handshake, HandshakeProof, HandshakeProofVerifier,
                        StrongProofVerifier
  steps.rs              x, u, K, M1, M2 over typed bytes (new, private)
  srp6.rs               Srp6<G>
src/hash/               HashFunc
```

No `src/primitives/` and no `src/big_number/` remain after Task 11.

---

## Task 1: Give PublicKey its own validated type

**Files:**
- Create: `src/typed/public_key.rs`
- Modify: `src/typed/field_element.rs`
- Modify: `src/typed/mod.rs`
- Test: `src/typed/tests.rs`
- Test: `tests/public_surface.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/typed/tests.rs`:

```rust
#[test]
fn a_public_key_is_a_distinct_validated_type() {
    let mut bytes = vec![0_u8; Group2048::N_BYTES];
    bytes[Group2048::N_BYTES - 1] = 2;

    let key = PublicKey::<Group2048>::from_bytes(&bytes).expect("a non-zero key");
    assert_eq!(key.as_bytes(), bytes.as_slice());
    assert!(format!("{key:?}").starts_with("PublicKey("));

    assert!(PublicKey::<Group2048>::from_bytes(&[0_u8; 256]).is_err());
    assert!(PublicKey::<Group2048>::from_bytes(&vec![0_u8; 257]).is_err());
}
```

Add `Group` to the existing import:

```rust
use crate::group::{Group, Group2048, Group4096, GroupOps};
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test typed::tests::a_public_key_is_a_distinct_validated_type`

Expected: FAIL because `PublicKey` is still an alias for `FieldElement`, so `Debug` prints `FieldElement(...)`.

- [ ] **Step 3: Create the newtype**

Create `src/typed/public_key.rs`:

```rust
use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::hex::{decode_hex, write_hex, FromHexString};
use super::FieldElement;
use crate::group::{Group, GroupOps};
use crate::{error::Srp6Error, Result};

/// A peer's public key `A` or `B`.
///
/// This is a distinct type so a verifier or a bare field element cannot be
/// passed where a peer key is expected. Construction reuses the field-element
/// validation: a key is never `0 mod N`.
pub struct PublicKey<G: Group>(FieldElement<G>);

impl<G: Group> PublicKey<G> {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl<G: GroupOps> PublicKey<G> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        FieldElement::from_bytes(bytes).map(Self)
    }

    pub(crate) fn from_field(group: &G, value: &G::Field) -> Self {
        Self(FieldElement::from_field(group, value))
    }

    pub(crate) fn to_field(&self, group: &G) -> G::Field {
        self.0.to_field(group)
    }
}

impl<G: Group> Clone for PublicKey<G> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<G: Group> PartialEq for PublicKey<G> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<G: Group> Eq for PublicKey<G> {}

impl<G: Group> AsRef<[u8]> for PublicKey<G> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<G: Group> From<PublicKey<G>> for Vec<u8> {
    fn from(value: PublicKey<G>) -> Self {
        value.to_bytes()
    }
}

impl<G: GroupOps> TryFrom<Vec<u8>> for PublicKey<G> {
    type Error = Srp6Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes(&bytes)
    }
}

impl<G: GroupOps> TryFrom<&[u8]> for PublicKey<G> {
    type Error = Srp6Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl<G: GroupOps> FromHexString for PublicKey<G> {
    fn try_from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(&decode_hex(hex)?)
    }
}

impl<G: Group> fmt::Display for PublicKey<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, self.as_bytes())
    }
}

impl<G: Group> fmt::Debug for PublicKey<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl<G: Group> Serialize for PublicKey<G> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de, G: GroupOps> Deserialize<'de> for PublicKey<G> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
```

- [ ] **Step 4: Wire the module and remove the alias**

In `src/typed/mod.rs`, add the module and change the re-exports:

```rust
mod field_element;
mod handshake;
mod hex;
mod proof;
mod public_key;
mod salt;
mod srp6;
mod strong_session_key;

#[cfg(test)]
mod tests;

pub use field_element::{FieldElement, Verifier};
pub use handshake::{
    Handshake, HandshakeProof, HandshakeProofVerifier, StrongProofVerifier, UserSecrets,
};
pub use hex::FromHexString;
pub use proof::Proof;
pub use public_key::PublicKey;
pub use salt::Salt;
pub use srp6::Srp6;
pub use strong_session_key::StrongSessionKey;
```

In `src/typed/field_element.rs`, delete the two lines that declare the `PublicKey` alias:

```rust
/// A peer's public key `A` or `B`.
pub type PublicKey<G> = FieldElement<G>;
```

Update the `FieldElement` doc paragraph to:

```rust
/// [`Verifier`] is the semantic name used for the server-stored `v`;
/// [`crate::PublicKey`] is a distinct type with its own validation.
```

- [ ] **Step 5: Run the tests**

Run: `cargo test`

Expected: PASS, including the new `PublicKey` test and the existing handshake tests.

- [ ] **Step 6: Extend the external surface test**

In `tests/public_surface.rs`, add `PublicKey` to the import:

```rust
use srp6::{
    FromHexString, Group2048, Proof, PublicKey, Salt, Srp6, StrongSessionKey, Username, Verifier,
};
```

Add:

```rust
#[test]
fn a_public_key_is_constructible_and_checked_at_the_boundary() {
    let mut bytes = vec![0_u8; Group2048::N_BYTES];
    bytes[Group2048::N_BYTES - 1] = 2;

    let key = PublicKey::<Group2048>::from_bytes(&bytes).expect("a non-zero key");
    assert_eq!(key.as_bytes(), bytes.as_slice());

    assert!(PublicKey::<Group2048>::from_bytes(&[0_u8; 256]).is_err());
}
```

Run: `cargo test --test public_surface`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/typed/public_key.rs src/typed/field_element.rs src/typed/mod.rs src/typed/tests.rs tests/public_surface.rs
git commit -m "refactor!: give the public key its own validated type"
```

---

## Task 2: Hash the private key x from typed bytes

**Files:**
- Create: `src/typed/steps.rs`
- Modify: `src/typed/mod.rs`
- Modify: `src/typed/srp6.rs`

- [ ] **Step 1: Write the failing regression test**

Create `src/typed/steps.rs` with only the test module first:

```rust
//! Hash-only protocol steps shared by the handshake and the golden vectors.
//!
//! These steps never touch the group arithmetic. Keeping them byte-based is
//! what removes the numeric round-trip from the production path.

use super::Salt;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Username;

    #[test]
    fn the_salt_is_hashed_with_its_leading_zeroes() {
        let username = Username::new("alice").expect("valid username");
        let salt = Salt::from(vec![0x00, 0xBE, 0xB2]);
        let with_zero = x_hash(&username, "password123", &salt);

        let trimmed = Salt::from(vec![0xBE, 0xB2]);
        let without_zero = x_hash(&username, "password123", &trimmed);

        assert_ne!(with_zero, without_zero);
    }
}
```

Add `pub(crate) mod steps;` to `src/typed/mod.rs`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test typed::steps::tests::the_salt_is_hashed_with_its_leading_zeroes`

Expected: FAIL because `x_hash` does not exist yet.

- [ ] **Step 3: Add the x step**

Replace the contents of `src/typed/steps.rs` with:

```rust
//! Hash-only protocol steps shared by the handshake and the golden vectors.
//!
//! These steps never touch the group arithmetic. Keeping them byte-based is
//! what removes the numeric round-trip from the production path.

use crate::credentials::{ClearTextPasswordRef, UsernameRef};
use crate::group::{Group, GroupOps};
use crate::hash::{Hash, HashFunc};

use super::Salt;

pub(crate) fn p_hash(
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
) -> Hash {
    // The WoW client uppercases the password at the point of use; the
    // username is already normalised by `Username::new`.
    #[cfg(feature = "wow-1-12-1")]
    let password: String = password.to_uppercase();

    HashFunc::new()
        .chain(username.as_bytes())
        .chain(b":")
        .chain(password.as_bytes())
        .finalize()
}

pub(crate) fn x_hash(
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
    salt: &Salt,
) -> Hash {
    // The salt is hashed as stored. Going through `BigNumber` trims leading
    // zero bytes before they reach the hash.
    HashFunc::new()
        .chain(salt.as_bytes())
        .chain(p_hash(username, password))
        .finalize()
}

pub(crate) fn private_key_x<G: GroupOps>(
    group: &G,
    username: UsernameRef<'_>,
    password: ClearTextPasswordRef<'_>,
    salt: &Salt,
) -> G::Exponent {
    group.exponent_from_hash(&x_hash(username, password, salt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Username;

    #[test]
    fn the_salt_is_hashed_with_its_leading_zeroes() {
        let username = Username::new("alice").expect("valid username");
        let salt = Salt::from(vec![0x00, 0xBE, 0xB2]);
        let with_zero = x_hash(&username, "password123", &salt);

        let trimmed = Salt::from(vec![0xBE, 0xB2]);
        let without_zero = x_hash(&username, "password123", &trimmed);

        assert_ne!(with_zero, without_zero);
    }
}
```

- [ ] **Step 4: Switch the handshake to the typed step**

In `src/typed/srp6.rs`, add `use super::steps;` to the existing imports. Keep the other `crate::big_number` and `crate::primitives` imports for now; remove `calculate_private_key_x` from the import list because no call site remains. Task 3 removes the rest together with their call sites, so the tree stays compilable after this commit.

Replace `generate_new_user_secrets`:

```rust
pub fn generate_new_user_secrets(
    &self,
    username: &Username,
    password: ClearTextPasswordRef,
) -> (Salt, Verifier<G>) {
    let salt: Vec<u8> = rng().random_iter().take(G::SALT_BYTES).collect();
    let salt = Salt::from(salt);
    let x = steps::private_key_x(&self.group, username, password, &salt);
    let verifier = self.group.field_pow(&self.group.generator(), &x);

    (salt, Verifier::from_field(&self.group, &verifier))
}
```

In `calculate_proof`, replace the two-line `calculate_private_key_x` call and the following `exponent_from_hash` line:

```rust
let x = calculate_private_key_x(
    username,
    password,
    &BigNumber::from_bytes_be(handshake.s.as_bytes()),
);
let x = self.group.exponent_from_hash(&x.to_vec());
```

with:

```rust
let x = steps::private_key_x(&self.group, username, password, &handshake.s);
```

- [ ] **Step 5: Run the tests**

Run: `cargo test`

Expected: PASS. The golden vectors still pass because the fixed salt starts with `0xBE`, so the leading-zero case is not in the fixtures.

- [ ] **Step 6: Commit**

```bash
git add src/typed/steps.rs src/typed/mod.rs src/typed/srp6.rs
git commit -m "fix: keep leading zeroes when hashing the salt"
```

---

## Task 3: Port the remaining hash steps from the numeric calculus

**Files:**
- Modify: `src/typed/steps.rs`
- Modify: `src/typed/srp6.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `src/typed/steps.rs`:

```rust
#[test]
fn the_generator_is_hashed_in_its_minimal_form() {
    let full = crate::group::Group2048.generator_bytes();
    let minimal = trim_leading_zeroes(&full);

    assert_eq!(minimal, [2_u8].as_slice());
}

#[test]
fn the_scrambler_hashes_the_fixed_width_keys() {
    let mut a_bytes = vec![0_u8; crate::group::Group2048::N_BYTES];
    a_bytes[crate::group::Group2048::N_BYTES - 1] = 2;
    let mut b_bytes = vec![0_u8; crate::group::Group2048::N_BYTES];
    b_bytes[crate::group::Group2048::N_BYTES - 1] = 3;

    let a = PublicKey::<crate::group::Group2048>::from_bytes(&a_bytes).expect("valid A");
    let b = PublicKey::<crate::group::Group2048>::from_bytes(&b_bytes).expect("valid B");

    let u = scrambler_u(&crate::group::Group2048, &a, &b);
    let expected = crate::group::Group2048
        .exponent_from_hash(&HashFunc::new().chain(&a_bytes).chain(&b_bytes).finalize());

    assert_eq!(u, expected);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test typed::steps::tests`

Expected: FAIL because `trim_leading_zeroes` and `scrambler_u` do not exist yet.

- [ ] **Step 3: Add u, K, M1, and M2**

In `src/typed/steps.rs`, extend the top imports:

```rust
use crate::credentials::{ClearTextPasswordRef, UsernameRef};
use crate::group::GroupOps;
use crate::hash::{Hash, HashFunc, STRONG_SESSION_KEY_LENGTH};

use super::{FieldElement, Proof, PublicKey, Salt, StrongSessionKey};
```

Add `use crate::group::Group;` to the test module; the tests name `Group2048::N_BYTES` and `generator_bytes` directly.

Append the functions before the test module:

```rust
pub(crate) fn scrambler_u<G: GroupOps>(
    group: &G,
    a: &PublicKey<G>,
    b: &PublicKey<G>,
) -> G::Exponent {
    let hash = HashFunc::new()
        .chain(a.as_bytes())
        .chain(b.as_bytes())
        .finalize();
    group.exponent_from_hash(&hash)
}

pub(crate) fn strong_session_key<G: GroupOps>(s: &FieldElement<G>) -> StrongSessionKey {
    strong_session_key_bytes(s.as_bytes())
}

pub(crate) fn strong_session_key_bytes(s: &[u8]) -> StrongSessionKey {
    debug_assert!(s.len().is_multiple_of(2));
    let half = s.len() / 2;
    let mut even = Vec::with_capacity(half);
    let mut odd = Vec::with_capacity(half);
    for pair in s.chunks_exact(2) {
        even.push(pair[0]);
        odd.push(pair[1]);
    }

    let even_hash = HashFunc::new().chain(&even).finalize();
    let odd_hash = HashFunc::new().chain(&odd).finalize();

    let mut key = [0_u8; STRONG_SESSION_KEY_LENGTH];
    for (i, (even, odd)) in even_hash.iter().zip(odd_hash.iter()).enumerate() {
        key[i * 2] = *even;
        key[i * 2 + 1] = *odd;
    }

    StrongSessionKey::from_bytes(&key).expect("the interleaved key is two hashes wide")
}

pub(crate) fn proof_m1<G: GroupOps>(
    group: &G,
    username: UsernameRef<'_>,
    salt: &Salt,
    a: &PublicKey<G>,
    b: &PublicKey<G>,
    k: &StrongSessionKey,
) -> Proof {
    let salt = pad_left(salt.as_bytes(), G::SALT_BYTES);
    let digest = HashFunc::new()
        .chain(hash_n_xor_g(group))
        .chain(HashFunc::new().chain(username.as_bytes()).finalize())
        .chain(salt)
        .chain(a.as_bytes())
        .chain(b.as_bytes())
        .chain(k.as_bytes())
        .finalize();

    Proof::from_bytes(&digest).expect("a proof is exactly one hash")
}

pub(crate) fn proof_m2<G: GroupOps>(
    a: &PublicKey<G>,
    m1: &Proof,
    k: &StrongSessionKey,
) -> Proof {
    let digest = HashFunc::new()
        .chain(a.as_bytes())
        .chain(m1.as_bytes())
        .chain(k.as_bytes())
        .finalize();

    Proof::from_bytes(&digest).expect("a proof is exactly one hash")
}

fn hash_n_xor_g<G: GroupOps>(group: &G) -> Hash {
    let mut n_hash = HashFunc::new().chain(&group.modulus_bytes()).finalize();
    // RFC 5054 hashes N at full width and g in its minimal form.
    let g_hash = HashFunc::new()
        .chain(trim_leading_zeroes(&group.generator_bytes()))
        .finalize();

    for (n, g) in n_hash.iter_mut().zip(g_hash.iter()) {
        *n ^= *g;
    }
    n_hash
}

fn trim_leading_zeroes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte != 0) {
        Some(start) => &bytes[start..],
        None => &bytes[bytes.len().saturating_sub(1)..],
    }
}

fn pad_left(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes.to_vec();
    }
    let mut padded = vec![0_u8; width];
    padded[width - bytes.len()..].copy_from_slice(bytes);
    padded
}
```

- [ ] **Step 4: Replace the remaining legacy call sites**

In `src/typed/srp6.rs`, delete the `crate::big_number` and `crate::primitives` imports. The only imports left should be:

```rust
use super::steps;
use crate::credentials::{ClearTextPasswordRef, Username};
use crate::group::{Group, GroupOps};
```

Replace `verify_proof` with:

```rust
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
```

Replace `calculate_proof` with:

```rust
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
```

Replace `verify_strong_proof` with:

```rust
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
```

- [ ] **Step 5: Run the tests**

Run: `cargo test`

Expected: PASS. The golden vectors pin the `H(N) xor H(g)` and salt padding behavior.

- [ ] **Step 6: Commit**

```bash
git add src/typed/steps.rs src/typed/srp6.rs
git commit -m "refactor: derive the remaining protocol steps from typed bytes"
```

---

## Task 4: Remove BigNumber from the production path

**Files:**
- Modify: `src/typed/proof.rs`
- Modify: `src/typed/strong_session_key.rs`
- Modify: `src/typed/hex.rs`
- Modify: `src/typed/tests.rs`
- Modify: `src/primitives/mod.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Replace Proof::ct_eq with subtle**

Run: `cargo add subtle@2.6 --offline`

Expected: `Cargo.toml` gains `subtle = "2.6"` and `Cargo.lock` updates.

In `src/typed/proof.rs`, replace the imports and `ct_eq`:

```rust
use subtle::ConstantTimeEq;
```

```rust
/// Constant-time equality, for comparing a received proof with an expected one.
pub fn ct_eq(&self, other: &Self) -> bool {
    self.0[..].ct_eq(&other.0[..]).into()
}
```

Delete `from_big_number`:

```rust
pub(crate) fn from_big_number(value: &BigNumber) -> Self {
    let padded = value.to_array_pad_zero_len(HASH_LENGTH);
    Self::from_bytes(&padded).expect("a hash is at most HASH_LENGTH bytes")
}
```

- [ ] **Step 2: Delete the StrongSessionKey numeric bridge**

In `src/typed/strong_session_key.rs`, delete:

```rust
pub(crate) fn from_big_number(value: &BigNumber) -> Self {
    Self::from_bytes(&value.to_array_pad_zero_len(STRONG_SESSION_KEY_LENGTH))
        .expect("the interleaved key is exactly two hashes wide")
}
```

Remove the `use crate::big_number::BigNumber;` line.

- [ ] **Step 3: Move the BigNumber hex impl out of the typed module**

In `src/typed/hex.rs`, delete:

```rust
use crate::big_number::BigNumber;
```

and:

```rust
impl FromHexString for BigNumber {
    fn try_from_hex(hex: &str) -> Result<Self> {
        BigNumber::try_from(hex).map_err(|_| Srp6Error::InvalidHexString)
    }
}
```

Add the impl to `src/primitives/mod.rs`:

```rust
impl crate::typed::FromHexString for BigNumber {
    fn try_from_hex(hex: &str) -> crate::Result<Self> {
        Self::from_hex_str_be(hex).map_err(|_| crate::error::Srp6Error::InvalidHexString)
    }
}
```

- [ ] **Step 4: Delete the numeric hex test**

In `src/typed/tests.rs`, delete:

```rust
use crate::big_number::BigNumber;
```

and:

```rust
#[test]
fn the_numeric_hex_path_round_trips_its_display() {
    let value = BigNumber::try_from_hex("BEB25379D1A8581EB5A727673A2441EE").unwrap();

    assert_eq!(BigNumber::try_from_hex(&value.to_string()).unwrap(), value);
}
```

The typed serde test added in Task 11 keeps the boundary format covered.

- [ ] **Step 5: Confirm the production path has no BigNumber**

Run: `rg -n "big_number|BigNumber|primitives" src/typed src/error.rs src/group.rs src/hash`

Expected: `src/typed` has no matches. `src/group.rs` and `src/hash/*` matches are inside `#[cfg(test)]` items or test modules.

- [ ] **Step 6: Run the tests**

Run: `cargo test`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/typed/proof.rs src/typed/strong_session_key.rs src/typed/hex.rs src/typed/tests.rs src/primitives/mod.rs
git commit -m "refactor: drop BigNumber from the production handshake"
```

---

## Task 5: Confine the numeric calculus to the test oracle

**Files:**
- Modify: `src/lib.rs`
- Modify: `src/hash/sha1.rs`
- Modify: `src/hash/sha512.rs`

- [ ] **Step 1: Gate the modules**

In `src/lib.rs`, change:

```rust
pub mod group;
mod primitives;
```

to:

```rust
pub mod group;
#[cfg(test)]
mod primitives;
```

and:

```rust
mod big_number;
```

to:

```rust
#[cfg(test)]
mod big_number;
```

- [ ] **Step 2: Gate the numeric hash helper**

In `src/hash/sha512.rs`, change:

```rust
use crate::big_number::BigNumber;
```

to:

```rust
#[cfg(test)]
use crate::big_number::BigNumber;
```

and:

```rust
pub(crate) fn hash_w_pad_len(a: &BigNumber, b: &BigNumber, pad: usize) -> BigNumber {
```

to:

```rust
#[cfg(test)]
pub(crate) fn hash_w_pad_len(a: &BigNumber, b: &BigNumber, pad: usize) -> BigNumber {
```

Make the same two changes in `src/hash/sha1.rs`.

- [ ] **Step 3: Confirm the production build is clean**

Run: `cargo build`

Expected: PASS with no `big_number` or `primitives` in the dependency graph.

Run: `cargo test`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs src/hash/sha1.rs src/hash/sha512.rs
git commit -m "test: confine the numeric calculus to the test oracle"
```

---

## Task 6: Add exponent byte conversions to GroupOps

**Files:**
- Modify: `src/group.rs`

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `src/group.rs`:

```rust
#[test]
fn exponent_bytes_round_trip() {
    let group = Group1024;
    let bytes = [0x01, 0x02, 0x03];

    let exponent = group.exponent_from_bytes(&bytes);
    let encoded = group.exponent_to_bytes(&exponent);

    assert_eq!(&encoded[encoded.len() - bytes.len()..], bytes.as_slice());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test group::tests::exponent_bytes_round_trip`

Expected: FAIL because the trait methods do not exist.

- [ ] **Step 3: Add the trait methods**

In `src/group.rs`, add to `GroupOps`:

```rust
fn exponent_from_bytes(&self, bytes: &[u8]) -> Self::Exponent;
fn exponent_to_bytes(&self, value: &Self::Exponent) -> Vec<u8>;
```

In the `closed_group!` macro, add:

```rust
fn exponent_from_bytes(&self, bytes: &[u8]) -> Self::Exponent {
    let width = <$exp>::BITS as usize / 8;
    let mut padded = vec![0_u8; width];
    if bytes.len() > width {
        padded.copy_from_slice(&bytes[bytes.len() - width..]);
    } else {
        padded[width - bytes.len()..].copy_from_slice(bytes);
    }
    <$exp>::from_be_slice(&padded)
}

fn exponent_to_bytes(&self, value: &Self::Exponent) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}
```

Replace `exponent_from_hash` with:

```rust
fn exponent_from_hash(&self, hash: &[u8]) -> Self::Exponent {
    self.exponent_from_bytes(hash)
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/group.rs
git commit -m "refactor: add exponent byte conversions to GroupOps"
```

---

## Task 7: Add deterministic entry points to the handshake driver

**Files:**
- Modify: `src/typed/srp6.rs`

- [ ] **Step 1: Split the random wrapper from the verifier core**

In `src/typed/srp6.rs`, replace `generate_new_user_secrets` with a public wrapper, a private core, and a test-only entry point:

```rust
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
```

- [ ] **Step 2: Split the random wrapper from the opening core**

Replace `start_handshake` with:

```rust
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
```

- [ ] **Step 3: Split the random wrapper from the proof core**

Replace the opening of `calculate_proof` with:

```rust
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
```

Delete the `let a_exp = self.group.random_exponent();` line from the core; the parameter replaces it. The rest of the existing body stays as it is. Add after the method:

```rust
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
```

- [ ] **Step 4: Run the tests**

Run: `cargo test`

Expected: PASS. The public methods are now thin randomness wrappers; the deterministic cores are the same code the golden vectors will drive.

- [ ] **Step 5: Commit**

```bash
git add src/typed/srp6.rs
git commit -m "refactor: expose deterministic handshake entry points for tests"
```

---

## Task 8: Pin the golden vectors through the public handshake

**Files:**
- Modify: `src/golden_vectors.rs`

- [ ] **Step 1: Drive the public handshake with fixed inputs**

Replace the imports and `snapshot` function in `src/golden_vectors.rs` with:

```rust
use std::fmt::Write as _;

use crate::big_number::BigNumber;
use crate::credentials::Username;
use crate::group::GroupOps;
#[cfg(feature = "wow-1-12-1")]
use crate::group::GroupWow;
use crate::typed::{steps, FromHexString, Salt, Srp6};
```

```rust
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex_trimmed(bytes: &[u8]) -> String {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    hex(&bytes[start..])
}

/// Everything a full handshake derives, in a stable text form.
#[allow(non_snake_case)]
fn snapshot<G: GroupOps>(group: G, username: &Username, password: &str, salt: &Salt) -> String {
    let a = group.exponent_from_bytes(&hex_to_bytes(PRIVATE_A_HEX));
    let b = group.exponent_from_bytes(&hex_to_bytes(PRIVATE_B_HEX));

    let srp = Srp6::new(group);
    let (salt, verifier) =
        srp.generate_new_user_secrets_with_fixed_salt(username, password, salt.clone());
    let (handshake, server) =
        srp.start_handshake_with_fixed_b(username, salt.clone(), verifier.clone(), b.clone());
    let (proof, client) = srp
        .calculate_proof_with_fixed_a(&handshake, username, password, a.clone())
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&server, &proof)
        .expect("the proof verifies");
    let strong_key = srp
        .verify_strong_proof(&client, &m2)
        .expect("the strong proof verifies");

    // `x` and `S` are not public values; recompute them from the same inputs.
    let helper = G::default();
    let x = steps::private_key_x(&helper, username, password, &salt);
    let u = steps::scrambler_u(&helper, &proof.A, &handshake.B);
    let v_field = verifier.to_field(&helper);
    let a_field = proof.A.to_field(&helper);
    let b_field = handshake.B.to_field(&helper);
    let g_field = handshake.g.to_field(&helper);
    let k_field = handshake.k.to_field(&helper);

    let s_host = helper.field_pow(
        &helper.field_mul(&a_field, &helper.field_pow(&v_field, &u)),
        &b,
    );
    let s_client_exp = helper.exponent_add(&a, &helper.exponent_mul(&u, &x));
    let s_client = helper.field_pow(
        &helper.field_sub(&b_field, &helper.field_mul(&k_field, &helper.field_pow(&g_field, &x))),
        &s_client_exp,
    );
    assert_eq!(
        helper.field_to_bytes(&s_host),
        helper.field_to_bytes(&s_client),
        "both sides must derive the same S"
    );

    let mut out = String::new();
    writeln!(out, "x = {}", hex_trimmed(&helper.exponent_to_bytes(&x)))
        .expect("writing to a String cannot fail");
    writeln!(out, "v = {}", hex_trimmed(verifier.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "A = {}", hex_trimmed(proof.A.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "B = {}", hex_trimmed(handshake.B.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "S = {}", hex_trimmed(&helper.field_to_bytes(&s_host)))
        .expect("writing to a String cannot fail");
    writeln!(out, "K = {}", hex_trimmed(strong_key.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "M1 = {}", hex_trimmed(proof.M1.as_bytes()))
        .expect("writing to a String cannot fail");
    writeln!(out, "M2 = {}", hex_trimmed(m2.as_bytes()))
        .expect("writing to a String cannot fail");
    out
}
```

- [ ] **Step 2: Update the vector entry points**

Replace the four vector functions with:

```rust
#[cfg(not(feature = "hash-sha1"))]
fn vectors_2048_sha512() -> String {
    snapshot(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(not(feature = "hash-sha1"))]
fn vectors_4096_sha512() -> String {
    snapshot(
        crate::group::Group4096,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(all(feature = "hash-sha1", not(feature = "wow-1-12-1")))]
fn vectors_2048_sha1() -> String {
    snapshot(
        crate::group::Group2048,
        &Username::new("alice").expect("valid username"),
        "password123",
        &salt(),
    )
}

#[cfg(feature = "wow-1-12-1")]
fn vectors_wow_sha1() -> String {
    snapshot(
        GroupWow,
        &Username::new("Thrall").expect("valid username"),
        "thrall",
        &salt(),
    )
}
```

- [ ] **Step 3: Update the interleave test and regeneration**

Replace the two `interleave_pads_a_session_key_with_a_zero_low_byte` bodies with:

```rust
#[test]
fn interleave_pads_a_session_key_with_a_zero_low_byte() {
    let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");

    let k = steps::strong_session_key_bytes(&s);

    assert_eq!(
        hex_trimmed(k.as_bytes()),
        include_str!("../tests/golden/interleave-zero-low-byte-sha512.txt").trim()
    );
}
```

Use `interleave-zero-low-byte-sha1.txt` in the `hash-sha1` variant.

In `regenerate_golden`, replace the `SessionKey` legacy calls with:

```rust
let s = hex_to_bytes("00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");
let k = steps::strong_session_key_bytes(&s);
```

and write `hex_trimmed(k.as_bytes())` to the fixture. Remove the now-unused `Proof` and `StrongSessionKey` imports.

- [ ] **Step 4: Run the golden tests**

Run: `cargo test golden`

Expected: PASS with every fixture byte unchanged.

- [ ] **Step 5: Run the full default suite**

Run: `cargo test`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/golden_vectors.rs
git commit -m "test: pin the golden vectors through the public handshake"
```

---

## Task 9: Port RFC appendix B to the typed handshake

**Files:**
- Modify: `src/rfc_5054_appendix_b.rs`

- [ ] **Step 1: Replace the numeric test with the typed handshake**

Replace the whole file with:

```rust
use std::fmt::Write as _;

use crate::credentials::{ClearTextPassword, Username};
use crate::group::{GroupOps, Group1024};
use crate::hash::HASH_LENGTH;
use crate::typed::{steps, FromHexString, Salt, Srp6};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex_trimmed(bytes: &[u8]) -> String {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let mut out = String::with_capacity((bytes.len() - start) * 2);
    for byte in &bytes[start..] {
        write!(out, "{byte:02X}").expect("writing to a String cannot fail");
    }
    out
}

/// The test vectors from RFC 5054 appendix B.
#[allow(non_snake_case)]
#[test]
fn test_appendix_b_srp_test_vectors() {
    let username = Username::new("alice").expect("valid username");
    let password = ClearTextPassword::from("password123");
    let salt = Salt::try_from_hex("BEB25379 D1A8581E B5A72767 3A2441EE").unwrap();

    let group = Group1024;
    let a = group.exponent_from_bytes(&hex_to_bytes(
        "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393",
    ));
    let b = group.exponent_from_bytes(&hex_to_bytes(
        "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20",
    ));

    let srp = Srp6::new(group);
    let (salt, verifier) =
        srp.generate_new_user_secrets_with_fixed_salt(&username, &password, salt);
    let (handshake, server) =
        srp.start_handshake_with_fixed_b(&username, salt.clone(), verifier.clone(), b.clone());
    let (proof, client) = srp
        .calculate_proof_with_fixed_a(&handshake, &username, &password, a.clone())
        .expect("the client can prove");
    let m2 = srp
        .verify_proof(&server, &proof)
        .expect("the proof verifies");
    let k = srp
        .verify_strong_proof(&client, &m2)
        .expect("the strong proof verifies");

    let x = steps::private_key_x(&group, &username, &password, &salt);
    assert_eq!(
        hex_trimmed(&group.exponent_to_bytes(&x)),
        "94B7555AABE9127CC58CCF4993DB6CF84D16C124",
        "private key x"
    );

    assert_eq!(
        hex_trimmed(verifier.as_bytes()),
        "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB",
        "password verifier v"
    );

    assert_eq!(
        hex_trimmed(proof.A.as_bytes()),
        "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B",
        "public key A"
    );

    assert_eq!(
        hex_trimmed(handshake.B.as_bytes()),
        "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58",
        "public key B"
    );

    let u = steps::scrambler_u(&group, &proof.A, &handshake.B);
    assert_eq!(
        hex_trimmed(&group.exponent_to_bytes(&u)),
        "CE38B9593487DA98554ED47D70A7AE5F462EF019",
        "scrambler u"
    );

    let v_field = verifier.to_field(&group);
    let a_field = proof.A.to_field(&group);
    let s_host = group.field_pow(&group.field_mul(&a_field, &group.field_pow(&v_field, &u)), &b);
    assert_eq!(
        hex_trimmed(&group.field_to_bytes(&s_host)),
        "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A",
        "session key S"
    );

    assert_eq!(proof.M1.as_bytes().len(), HASH_LENGTH, "M1 is one hash long");
    assert_eq!(m2.as_bytes().len(), HASH_LENGTH, "M2 is one hash long");
    assert_eq!(k.as_bytes().len(), 2 * HASH_LENGTH, "K is two hashes long");
}
```

- [ ] **Step 2: Run the appendix B test**

Run: `cargo test --no-default-features --features test-rfc-5054-appendix-b --lib`

Expected: PASS. Every RFC value is derived through the public `Srp6` handshake; `x` and `S` are recomputed only because they are not public values.

- [ ] **Step 3: Commit**

```bash
git add src/rfc_5054_appendix_b.rs
git commit -m "test: port the RFC appendix B vectors to the typed handshake"
```

---

## Task 10: Replace the const-vs-dynamic group test

**Files:**
- Modify: `src/group.rs`

- [ ] **Step 1: Replace the oracle import and test macro**

In the `#[cfg(test)] mod tests` of `src/group.rs`, replace the imports:

```rust
use super::*;
use crate::credentials::Username;
use crate::primitives::*;
use crate::typed::FromHexString;
```

with:

```rust
use super::*;
use crate::credentials::Username;
use crate::typed::{steps, FromHexString, Salt};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, Odd,
};
```

Replace the `const_group_matches_dynamic!` macro body with:

```rust
macro_rules! const_group_matches_dynamic {
    ($name:ident, $field:ident, $uint:ident, $g:expr, $group:ident) => {
        #[test]
        fn $name() {
            let group = $group;
            let salt = Salt::try_from_hex("BEB25379D1A8581EB5A727673A2441EE").expect("valid hex");
            let username = Username::new("alice").expect("valid username");
            let x = steps::private_key_x(&group, &username, "password123", &salt);

            let n_bytes = (<$uint>::BITS / 8) as usize;
            let x_bytes = group.exponent_to_bytes(&x);
            assert!(x_bytes.len() <= n_bytes);
            let mut padded = vec![0_u8; n_bytes];
            padded[n_bytes - x_bytes.len()..].copy_from_slice(&x_bytes);
            let exponent = <$uint>::from_be_slice(&padded);

            let generator = <$uint>::from_u8($g);
            let verifier = $field::new(&generator).pow(&exponent).retrieve();

            let modulus = BoxedUint::from_be_slice(&group.modulus_bytes(), <$uint>::BITS)
                .expect("the modulus fits");
            let params = BoxedMontyParams::new(Odd::new(modulus).into_option().expect("odd N"));
            let dynamic = BoxedMontyForm::new(BoxedUint::from_u8($g), &params)
                .pow(&BoxedUint::from_be_slice(&padded, <$uint>::BITS).expect("the exponent fits"))
                .retrieve()
                .to_be_bytes_trimmed_vartime()
                .to_vec();

            let actual = verifier.to_be_bytes();
            assert_eq!(&actual[actual.len() - dynamic.len()..], dynamic.as_slice());
        }
    };
}
```

- [ ] **Step 2: Run the group tests**

Run: `cargo test group::tests`

Expected: PASS. The const field still matches a direct `BoxedMontyForm` calculation, without the numeric oracle.

- [ ] **Step 3: Commit**

```bash
git add src/group.rs
git commit -m "test: compare the const field against crypto-bigint directly"
```

---

## Task 11: Delete the numeric protocol layer

**Files:**
- Delete: `src/primitives/` (all files)
- Delete: `src/big_number/` (all files)
- Modify: `src/lib.rs`
- Modify: `src/hash/sha1.rs`
- Modify: `src/hash/sha512.rs`
- Modify: `src/golden_vectors.rs`
- Modify: `src/typed/tests.rs`

- [ ] **Step 1: Delete the modules**

Run:

```bash
git rm -r src/primitives src/big_number
```

In `src/lib.rs`, delete:

```rust
#[cfg(test)]
mod primitives;
```

and:

```rust
#[cfg(test)]
mod big_number;
```

- [ ] **Step 2: Remove the numeric hash helper and its tests**

In `src/hash/sha512.rs`, delete:

```rust
#[cfg(test)]
use crate::big_number::BigNumber;
```

```rust
#[cfg(test)]
pub(crate) fn hash_w_pad_len(a: &BigNumber, b: &BigNumber, pad: usize) -> BigNumber {
    BigNumber::from_bytes_be(
        HashFunc::new()
            .chain(a.to_array_pad_zero_len(pad))
            .chain(b.to_array_pad_zero_len(pad))
            .finalize()
            .as_slice(),
    )
}
```

Delete the `should_hash_2_big_numbers_with_sha512` test module. Make the same removals in `src/hash/sha1.rs`.

- [ ] **Step 3: Remove the last numeric test**

In `src/golden_vectors.rs`, delete the `text_and_byte_formats_do_not_move` test and the `use crate::big_number::BigNumber;` import.

- [ ] **Step 4: Add a typed serde round-trip test**

In `src/typed/tests.rs`, add:

```rust
#[test]
fn the_boundary_types_round_trip_through_json() {
    let salt = Salt::try_from_hex("00AB").expect("valid hex");
    let json = serde_json::to_string(&salt).expect("the salt serializes");
    let back: Salt = serde_json::from_str(&json).expect("the salt deserializes");
    assert_eq!(salt, back);

    let proof = Proof::try_from_hex(&"00".repeat(HASH_LENGTH)).expect("valid proof");
    let json = serde_json::to_string(&proof).expect("the proof serializes");
    let back: Proof = serde_json::from_str(&json).expect("the proof deserializes");
    assert_eq!(proof, back);
}
```

- [ ] **Step 5: Remove the unused hex-literal dependency**

Run: `rg -n "hex_literal|hex!" src`

Expected: no matches. Remove `hex-literal = "1.0"` from `[dependencies]` in `Cargo.toml`.

- [ ] **Step 6: Confirm no numeric references remain**

Run: `rg -n "big_number|BigNumber|primitives" src tests examples`

Expected: no matches except the stale `crate::primitives` doc reference in `src/wow.rs`, which Task 12 fixes.

Run: `cargo test`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/hash/sha1.rs src/hash/sha512.rs src/golden_vectors.rs src/typed/tests.rs
git commit -m "refactor!: delete the numeric protocol layer"
```

---

## Task 12: Final cleanup and verification

**Files:**
- Modify: `src/wow.rs`
- Modify: `src/typed/mod.rs`
- Modify: `src/typed/field_element.rs`
- Modify: `src/golden_vectors.rs`

- [ ] **Step 1: Fix the stale docs**

In `src/wow.rs`, replace the `crate::primitives` reference with `crate::credentials`.

In `src/typed/mod.rs`, update the module docs so `PublicKey` is a distinct validated type, not an alias.

In `src/typed/field_element.rs`, update the `FieldElement` doc so `Verifier` is the semantic name for `v` and `PublicKey` is a separate type.

In `src/golden_vectors.rs`, update the regeneration command to:

```text
cargo test --lib -- --ignored regenerate_golden
cargo test --lib --no-default-features --features wow-1-12-1 -- --ignored regenerate_golden
```

- [ ] **Step 2: Run the full CI gate**

Run: `just ci-check`

Expected: fmt, clippy, check, all four test flavours, and docs pass. The audit step is advisory.

- [ ] **Step 3: Confirm the final shape**

Run: `rg -n "type PublicKey|struct PublicKey|type Salt|struct Salt|type Proof|struct Proof|type StrongSessionKey|struct StrongSessionKey|type Verifier" src`

Expected: `PublicKey`, `Salt`, `Proof`, and `StrongSessionKey` are structs only in `src/typed/`. `Verifier` is a type alias only in `src/typed/field_element.rs`.

Run: `cargo build`

Expected: PASS with no numeric layer in the dependency graph.

- [ ] **Step 4: Commit**

```bash
git add src/wow.rs src/typed/mod.rs src/typed/field_element.rs src/golden_vectors.rs
git commit -m "chore: remove the last numeric references"
```

---


---

## Verification matrix

| Command | What it pins |
|---|---|
| `cargo test` | default sha512 handshake and golden vectors |
| `cargo test --no-default-features --features hash-sha1 --lib` | SHA-1 variants |
| `cargo test --no-default-features --features wow-1-12-1 --lib` | WoW group, k=3, uppercased password |
| `cargo test --no-default-features --features test-rfc-5054-appendix-b --lib` | RFC appendix B oracle |
| `cargo clippy --locked --all-targets -- -D warnings` | no new lint debt |
| `cargo fmt --all -- --check` | formatting |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | no broken or private links |
| `just ci-check` | the same gates CI runs |

## Self-review notes

- The `Verifier` alias stays because the legacy layer never made it a distinct type and it has no invariant beyond `FieldElement`. Promoting it later is a separate decision.
- `Proof` stays one type for M1 and M2, matching the typed API; the role is carried by the field and method, not a second type.
- Golden vectors drive the `#[cfg(test)]` deterministic entry points on `Srp6`, so the public handshake is the code under test. `x` and `S` are recomputed only because the public API does not expose those intermediates.
- RFC appendix B and the direct crypto-bigint group check replace the numeric oracle; the final crate has one implementation.
- The typed names are the only protocol vocabulary left; no numeric aliases survive Task 11.
