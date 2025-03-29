use serde::{Deserialize, Serialize};

pub use srp6::{PasswordVerifier, Salt, UserSecrets, Username};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRegistration(pub UserSecrets);

impl UserRegistration {
    pub fn username(&self) -> &Username {
        &self.0.username
    }

    pub fn salt(&self) -> &Salt {
        &self.0.salt
    }

    pub fn verifier(&self) -> &PasswordVerifier {
        &self.0.verifier
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRegistrationJson {
    pub username: String,
    pub salt: String,
    pub verifier: String,
}

impl From<UserRegistrationJson> for UserRegistration {
    fn from(json: UserRegistrationJson) -> Self {
        let username = Username::from(json.username);
        let salt = Salt::from_hex_str_be(&json.salt)
            .map_err(|_err| "salt was invalid!")
            .unwrap();
        let verifier = PasswordVerifier::from_hex_str_be(&json.verifier)
            .map_err(|_err| "verifier was invalid!")
            .unwrap();

        UserRegistration(UserSecrets {
            username,
            salt,
            verifier,
        })
    }
}
