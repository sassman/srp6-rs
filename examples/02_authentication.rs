use srp6::prelude::*;

const USER_PASSWORD: ClearTextPasswordRef = "password123";

// a println -like macro, to nicely format the key
macro_rules! printkeyln {
    ($label:expr, $key:expr) => {
        println!(
            " - {} = \n\n    {}\n",
            $label,
            $key.to_string().replace("\n", "\n    ")
        );
    };
}

fn main() {
    // the server looks up the user details by a received username
    let user = mocked::lookup_user_details("alice");

    // the server creates a handshake
    let (handshake, proof_verifier) = Srp6_4096::default().start_handshake(&user);
    assert_eq!(handshake.B.num_bytes(), Srp6_4096::KEY_LEN);
    println!(
        "## Simulating a Server and {} is our client.",
        user.username
    );
    println!("server secrets are:");
    printkeyln!("public key  [B]", &proof_verifier.server_keys.0);
    printkeyln!("private key [b]", &proof_verifier.server_keys.1);
    println!();
    println!("## {}'s secrets", user.username);
    printkeyln!("verifier [v]", &user.verifier);
    printkeyln!("salt     [s]", &user.salt);
    println!();
    println!("## {}'s handshake", user.username);
    printkeyln!("salt               [s]", handshake.s);
    printkeyln!("server public key  [B]", &handshake.B);
    printkeyln!("prime modulus      [N]", &handshake.N);
    printkeyln!("generator modulus  [g]", &handshake.g);
    printkeyln!("multiplier         [k]", &handshake.k);
    println!();

    // the client provides proof to the server
    let (proof, strong_proof_verifier) = handshake
        .calculate_proof(user.username.as_str(), USER_PASSWORD)
        .unwrap();
    assert_eq!(proof.A.num_bytes(), Srp6_4096::KEY_LEN);
    assert_eq!(
        proof.M1.num_bytes(),
        HASH_LENGTH,
        "sha1 or sha-512 hash length expected"
    );
    println!("### Next Step: sending this handshake to the client");
    println!();
    println!("## Simulating client {}", user.username);
    println!("### {}'s proof", user.username);
    printkeyln!("proof      [M1]", &proof.M1);
    printkeyln!("public key  [A]", &proof.A);
    println!();

    // the server verifies this proof
    let strong_proof = proof_verifier.verify_proof(&proof);
    assert!(strong_proof.is_ok());
    let (strong_proof, session_key_server) = strong_proof.unwrap();
    println!("### Next Step: sending proof to the server");
    println!();
    println!(
        "## Simulating a Server and {} is our client.",
        user.username
    );
    printkeyln!("strong proof         [M2]", &strong_proof);
    printkeyln!("session key (server)  [K]", &session_key_server);
    println!();
    println!("[server] 🎉🥳🎊🍾🎈 Proof of the client successfully verified");

    // the client needs to verify the strong proof
    let session_key_client = strong_proof_verifier
        .verify_strong_proof(&strong_proof)
        .unwrap();
    println!("### Next Step: sending this strong proof to the client");
    println!();
    println!("## Simulating client {}", user.username);
    printkeyln!("session key (client) [K]", &session_key_client);
    println!();
    println!("[client] 🎉🥳🎊🍾🎈 Proof of the server successfully verified");
}

mod mocked {
    use super::*;

    /// normally salt and verifier is retrieved rom a user database
    pub fn lookup_user_details(username: UsernameRef) -> UserSecrets {
        let (salt, verifier) =
            Srp6_4096::default().generate_new_user_secrets(username, USER_PASSWORD);

        UserSecrets {
            username: username.to_owned(),
            salt,
            verifier,
        }
    }
}
