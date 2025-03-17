use srp6::prelude::*;

const USER_PASSWORD: ClearTextPasswordRef<'static> = "secret-password";

fn main() {
    // the server looks up the user details by a received username
    let user = mocked::lookup_user_details("Bob");

    // the server creates a handshake
    let (handshake, proof_verifier) = Srp6_4096::default().start_handshake(&user);
    assert_eq!(handshake.B.num_bytes(), Srp6_4096::KEY_LEN);
    println!(
        "## Simulating a Server and {} is our client.",
        user.username
    );
    println!("host secrets are:");
    println!(
        " - public key          [B] = {:?}",
        &proof_verifier.server_keys.0
    );
    println!(
        " - private key         [b] = {:?}",
        &proof_verifier.server_keys.1
    );
    println!();
    println!("{}'s secrets are:", user.username);
    println!(" - verifier          [v] = {:?}", &user.verifier);
    println!(" - salt              [s] = {:?}", &user.salt);
    println!();
    println!("{}'s handshake looks like:", user.username);
    println!(" - salt              [s] = {:?}", &handshake.s);
    println!(" - server public key [B] = {:?}", &handshake.B);
    println!(" - prime modulus     [N] = {:?}", &handshake.N);
    println!(" - generator modulus [g] = {:?}", &handshake.g);
    println!(" - multiplier        [k] = {:?}", &handshake.k);
    println!();
    println!("### Next Step: sending this handshake to the client");

    // the client provides proof to the server
    let (proof, strong_proof_verifier) = handshake
        .calculate_proof(user.username.as_str(), USER_PASSWORD)
        .unwrap();
    assert_eq!(proof.A.num_bytes(), Srp6_4096::KEY_LEN);
    assert_eq!(proof.M1.num_bytes(), 20, "sha1 hash length expected");
    println!();
    println!("## Simulating client {}", user.username);
    println!("{}'s proof looks like:", user.username);
    println!(" - Proof          [M1] = {:?}", &proof.M1);
    println!(" - {}s public key [A] = {:?}", user.username, &proof.A);
    println!();
    println!("### Next Step: sending proof to the server");

    // the server verifies this proof
    let strong_proof = proof_verifier.verify_proof(&proof);
    assert!(strong_proof.is_ok());
    let (strong_proof, session_key_server) = strong_proof.unwrap();
    println!();
    println!(
        "## Simulating a Server and {} is our client.",
        user.username
    );
    println!(" - Strong Proof     [M2] = {:?}", &strong_proof);
    println!(" - Session Key      [K]  = {:?}", &session_key_server);
    println!();
    println!("🎉🥳🎊🍾🎈 Proof of the client successfully verified");
    println!("### Next Step: sending this strong proof to the client");

    // the client needs to verify the strong proof
    let session_key_client = strong_proof_verifier
        .verify_strong_proof(&strong_proof)
        .unwrap();
    println!();
    println!("## Simulating client {}", user.username);
    println!(" - Strong Proof     [M2] = {:?}", &strong_proof);
    println!(" - Session Key       [K] = {:?}", &session_key_client);
    println!();
    println!("🎉🥳🎊🍾🎈 Proof of the server successfully verified");
}

mod mocked {
    use super::*;

    /// normally salt and verifier is retrieved rom a user database
    pub fn lookup_user_details(username: UsernameRef) -> UserDetails {
        let (salt, verifier) =
            Srp6_4096::default().generate_new_user_secrets(username, USER_PASSWORD);

        UserDetails {
            username: username.to_owned(),
            salt,
            verifier,
        }
    }
}
