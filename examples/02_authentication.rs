use srp6::*;

const USER_PASSWORD: &ClearTextPassword = "secret-password";

fn main() {
    // the server looks up the user details by a received username
    let user = mocked::lookup_user_details("Bob");

    // the server creates a handshake
    let key_length_bits = 4096;
    let (handshake, proof_verifier) = Srp6_4096::default().start_handshake(&user);
    assert_eq!(handshake.B.num_bytes(), key_length_bits / 8);
    println!("Simulating a Server and {} is our client.", user.username);
    println!("{}'s handshake looks like:", user.username);
    println!(" - salt              [s] = {:?}", &handshake.s);
    println!(" - server public key [B] = {:?}", &handshake.B);
    println!(" - prime modulus     [N] = {:?}", &handshake.N);
    println!(" - generator modulus [g] = {:?}", &handshake.g);
    println!(" - multiplier        [k] = {:?}", &handshake.k);
    println!();
    println!("Next Step: sending this handshake to the client");

    // the client provides proof to the server
    let proof = handshake
        .calculate_proof(user.username.as_str(), USER_PASSWORD)
        .unwrap();
    assert_eq!(proof.A.num_bytes(), key_length_bits / 8);
    assert_eq!(proof.M1.num_bytes(), 20, "sha1 hash length expected");
    println!();
    println!("Simulating client {}", user.username);
    println!("{}'s proof looks like:", user.username);
    println!(" - Proof          [M1] = {:?}", &proof.M1);
    println!(" - {}s public key [A] = {:?}", user.username, &proof.A);
    println!();
    println!("Next Step: sending proof to the server");

    // the server verifies this proof
    let strong_proof = proof_verifier.verify_proof(&proof);
    assert!(strong_proof.is_ok());
    let strong_proof = strong_proof.unwrap();
    println!();
    println!("Simulating a Server and {} is our client.", user.username);
    println!(" - Strong Proof     [M2] = {:?}", &strong_proof);
    println!();
    println!("🎉🥳🎊🍾🎈 Proof successfully verified");
    println!("Next Step: sending this strong proof to the client");
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
