use srp6::prelude::*;

const USER_PASSWORD: ClearTextPasswordRef = "password123";

// a println-like macro, to nicely format the key
macro_rules! printkeyln {
    ($label:expr, $key:expr) => {
        println!(" - {} = \n\n    {}\n", $label, $key);
    };
}

/// second part of a auth flow, the authentication.
/// run with: `cargo run --example 02_authentication`
fn main() {
    // the server looks up the user details by a received username
    let alice = Username::new("alice").expect("valid username");
    let srp = Srp6_4096::default();
    let user = mocked::lookup_user_details(&srp, &alice);

    // the server creates a handshake
    let (handshake, proof_verifier) = srp
        .start_handshake(
            user.username(),
            user.salt().clone(),
            user.verifier().clone(),
        )
        .expect("the handshake starts");
    println!(
        "## Simulating a Server and {} is our client.",
        user.username()
    );
    println!("server secrets are:");
    printkeyln!("public key  [B]", proof_verifier.public_key());
    println!();
    println!("## {}'s secrets", user.username());
    printkeyln!("verifier [v]", user.verifier());
    printkeyln!("salt     [s]", user.salt());
    println!();
    println!("## {}'s handshake", user.username());
    printkeyln!("salt               [s]", handshake.salt());
    printkeyln!("server public key  [B]", handshake.public_key());
    printkeyln!("prime modulus      [N]", srp.modulus());
    printkeyln!("generator          [g]", handshake.generator());
    printkeyln!("multiplier         [k]", handshake.multiplier());
    println!();

    // the client provides proof to the server
    let (proof, strong_proof_verifier) = srp
        .calculate_proof(&handshake, user.username(), USER_PASSWORD)
        .expect("the client can prove");
    assert_eq!(
        proof.proof().as_bytes().len(),
        HASH_LENGTH,
        "sha1 or sha-512 hash length expected"
    );
    println!("### Next Step: sending this handshake to the client");
    println!();
    println!("## Simulating client {}", user.username());
    println!("### {}'s proof", user.username());
    printkeyln!("proof      [M1]", proof.proof());
    printkeyln!("public key  [A]", proof.public_key());
    println!();

    // the server verifies this proof
    let strong_proof = srp
        .verify_proof(&proof_verifier, &proof)
        .expect("the proof verifies");
    println!("### Next Step: sending proof to the server");
    println!();
    println!(
        "## Simulating a Server and {} is our client.",
        user.username()
    );
    printkeyln!("strong proof         [M2]", strong_proof);
    printkeyln!(
        "session key (server)  [K]",
        strong_proof_verifier.session_key()
    );
    println!();
    println!("[server] 🎉🥳🎊🍾🎈 Proof of the client successfully verified");

    // the client needs to verify the strong proof
    let session_key_client = srp
        .verify_strong_proof(&strong_proof_verifier, &strong_proof)
        .expect("the strong proof verifies");
    println!("### Next Step: sending this strong proof to the client");
    println!();
    println!("## Simulating client {}", user.username());
    printkeyln!("session key (client) [K]", session_key_client);
    println!();
    println!("[client] 🎉🥳🎊🍾🎈 Proof of the server successfully verified");
}

mod mocked {
    use super::*;

    /// normally salt and verifier is retrieved from a user database
    pub fn lookup_user_details(_srp: &Srp6_4096, username: UsernameRef) -> UserSecrets<Group4096> {
        // let (salt, verifier) = srp.generate_new_user_secrets(username, USER_PASSWORD);

        UserSecrets::new(
            username.to_owned(),
            Salt::try_from_hex("CB7DDE21959B32FA81BF1CD90794F07C6CAE0B2A00F569E43EC238088D5CC9D89E7A534CD02E463F156DE599EBF6935802CF8ACB15C7B1BD9CD77B3E4D755FF51135857F34F11E77AE93E95837109F8079AB47B5A68ECF1401138F29A89D9EC01461E547284C1D56CBA232F8BB131CDDED7FCEFB3EA4617E398550B58883359BA11D4FD30C9CA3627CCF16FE07DF240EDBD4D6B7FE7C18584C0C75A570BDEC112E09FCEF9AD0C8CF53A45BFEA99E92D1C6CD4BD366A499EBBDA99E821F348201AE7F7FDFECEE5C4E50ECF79C8F1B08F0AB64A827048E2F427EDFB4B082FE64564BB31E167A0837FE524B388FE41AA6751C8A258DBCCC4707E82F679BDED243B500386B9C5133A655972CC1167A19CE53218CE32EC8133BD90FBD6EE1F9CE0A630823C777FDB447A499DFE22E5A63CD8399E4886EBEA4553A6EC246B4D75EA55E8097F066962296E72A9650FB2BE328CC5395CECDBAEA2BCF43938CF634E00B7F3650DBA34F3DEC50DC3F3007EFA49531295EC64C65E786A75FFAF01CE8A586ACF45238A764C7896EABAF032CAB199F50035A32E4FC1BDE5FABFC213B3BA64AE1F0BC43737293D6B3B457AF276493E99CFBCCD0DF6D60615874E916DB0EC51F48F87FAD95DD8D22118C628C885A3661401512889FFC9CF2ECBD750985DE2D60F400336276AEA0AD36F9D598EC07F19FC0421D7F4B6F1C8D7733DC7FE5EA9FFC0C").unwrap(),
            Verifier::try_from_hex("5EE75868F72D4A3E33468D301FF4BC2055312BDBCEA86C299F397FBB501C28A587064BC1E6AEBB9FC25C4BC766094635E225DC316AD1F14BA1926EB8D2EEC19B33E245A5387ED38279C07C1143A08F88FD1EEC2C87C55CC34F84389CF6785119346552EE04FD67F37810A3C9057B103BDFE5CB2532638ECB93610D90531275145F536C30F5EEE38FD584D31A36C4F1AB9FBF4B2DBF9FAFC302D8FF795185F97DD4B18DCFB8DE18A24834BECEA2D3E26A7F109F2828C07699C5E0E267F82455F664E233CD136A9B6555C04B1E9AABAD428487E7A1E72CBBA6D14321992E188A37AB563C5CE5C33FD1E23C0FC03FC998CC858308CAA4371E10F2444C9E2E77FF9059359FBD7404BB8B1A93D9DAFEE16DAC5D23F1FD4B8BBDB0A550C5C1BB2C8DAAFEB51B03DDC7B7917CC415FABCDB639C6A65AA2645D9210670B413E2A415055DAB55DB39442949F6E61E6A03E9C3B762AAEC95A8A78681DAB9FD6445C60BB3D9E8A27A1AF8B59F67AC629CFB434AF458644E1BD4861B919DD2391D88F05B205A8185C269440F555A6EEF70462AF4D4B235F33FC3B0214D062296CC4FD08CD39A4C6E6CCBD7B2952E0B7F0D4ED81B46000E37427A1400521AEC2CEC735CFEC36D06B0EFD9E6795272073ABEA4145742F5BF7F1A0DDACB1DF3A02688240D49D0B11CB538B64DFDE7038616FED8263C4D1429FDA7F6AA3AED67FE78C94A6E60339B").unwrap(),
        )
    }
}
