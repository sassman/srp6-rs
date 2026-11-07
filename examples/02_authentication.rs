use srp6::prelude::*;

const USER_PASSWORD: ClearTextPasswordRef = "password123";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// a println-like macro, to nicely format the key
macro_rules! printkeyln {
    ($label:expr, $key:expr) => {
        println!(" - {} = \n\n    {}\n", $label, $key);
    };
}

fn main() {
    // the server looks up the user details by a received username
    let alice = Username::new("alice").expect("valid username");
    let srp = Srp6_4096::default();
    let user = mocked::lookup_user_details(&srp, &alice);

    // the server creates a handshake
    let (handshake, proof_verifier) =
        srp.start_handshake(&user.username, user.salt.clone(), user.verifier);
    println!(
        "## Simulating a Server and {} is our client.",
        user.username
    );
    println!("server secrets are:");
    printkeyln!(
        "public key  [B]",
        hex(&srp.group.field_to_bytes(&proof_verifier.B))
    );
    println!();
    println!("## {}'s secrets", user.username);
    printkeyln!(
        "verifier [v]",
        hex(&srp.group.field_to_bytes(&user.verifier))
    );
    printkeyln!("salt     [s]", hex(&user.salt));
    println!();
    println!("## {}'s handshake", user.username);
    printkeyln!("salt               [s]", hex(&handshake.s));
    printkeyln!(
        "server public key  [B]",
        hex(&srp.group.field_to_bytes(&handshake.B))
    );
    printkeyln!("prime modulus      [N]", hex(&srp.group.modulus_bytes()));
    printkeyln!(
        "generator modulus  [g]",
        hex(&srp.group.field_to_bytes(&handshake.g))
    );
    printkeyln!(
        "multiplier         [k]",
        hex(&srp.group.field_to_bytes(&handshake.k))
    );
    println!();

    // the client provides proof to the server
    let (proof, strong_proof_verifier) = srp
        .calculate_proof(&handshake, &user.username, USER_PASSWORD)
        .expect("the client can prove");
    assert_eq!(
        proof.M1.num_bytes(),
        HASH_LENGTH,
        "sha1 or sha-512 hash length expected"
    );
    println!("### Next Step: sending this handshake to the client");
    println!();
    println!("## Simulating client {}", user.username);
    println!("### {}'s proof", user.username);
    printkeyln!("proof      [M1]", hex(&proof.M1.to_vec()));
    printkeyln!("public key  [A]", hex(&proof.A));
    println!();

    // the server verifies this proof
    let strong_proof = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    println!("### Next Step: sending proof to the server");
    println!();
    println!(
        "## Simulating a Server and {} is our client.",
        user.username
    );
    printkeyln!("strong proof         [M2]", hex(&strong_proof.to_vec()));
    printkeyln!(
        "session key (server)  [K]",
        hex(&strong_proof_verifier.K.to_vec())
    );
    println!();
    println!("[server] 🎉🥳🎊🍾🎈 Proof of the client successfully verified");

    // the client needs to verify the strong proof
    let session_key_client = srp
        .verify_strong_proof(&strong_proof_verifier, &strong_proof)
        .expect("the strong proof verifies");
    println!("### Next Step: sending this strong proof to the client");
    println!();
    println!("## Simulating client {}", user.username);
    printkeyln!(
        "session key (client) [K]",
        hex(&session_key_client.to_vec())
    );
    println!();
    println!("[client] 🎉🥳🎊🍾🎈 Proof of the server successfully verified");
}

mod mocked {
    use super::*;

    /// normally salt and verifier is retrieved from a user database
    pub fn lookup_user_details(srp: &Srp6_4096, username: UsernameRef) -> UserSecrets<Group4096> {
        let (salt, verifier) = srp.generate_new_user_secrets(username, USER_PASSWORD);

        UserSecrets {
            username: username.to_owned(),
            salt,
            verifier,
        }
    }
}
