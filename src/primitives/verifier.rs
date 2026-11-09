use super::montgomery::{field, field_bytes, monty_params};
use super::{Generator, PasswordVerifier, PrimeModulus, PrivateKey};

/// here we calculate the `PasswordVerifier` called `v` based on `x`
/// **Note**: something that only needs to be done on user pw change, or user creation
/// `x`:  Private key (derived from p and s)
/// `v`:  Password verifier
/// `g`:  A generator modulo N
/// `N`:  A large safe prime (N = 2q+1, where q is prime)
/// formula: `v = g^x % N`
#[allow(non_snake_case)]
pub fn calculate_password_verifier_v(
    N: &PrimeModulus,
    g: &Generator,
    x: &PrivateKey,
) -> PasswordVerifier {
    let params = monty_params(N);
    let v = field(g, &params).pow(x.as_boxed_uint());

    PasswordVerifier::from_bytes_be(&field_bytes(&v))
}
