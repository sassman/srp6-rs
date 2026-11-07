use srp6::prelude::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    // this is what a user would enter in a form / terminal
    let new_username = Username::new("alice").expect("valid username");
    let user_password: ClearTextPasswordRef = "password123";

    // Reminder: choose always a Srp6_BITS type that is strong like 2048 or 4096
    let srp = Srp6_4096::default();
    let (salt_s, verifier_v) = srp.generate_new_user_secrets(&new_username, user_password);
    let verifier_v = srp.group.field_to_bytes(&verifier_v);

    println!("Simulating a server and signup with user {}", new_username);
    println!("{}'s secrets are:", new_username);
    println!(" - Salt [s]:");
    println!("   - {}", hex(&salt_s));
    println!(" - Password verifier [v]:");
    println!("   - {}", hex(&verifier_v));
    println!();
    println!("This is a one time action, normally this data is stored in a user database");
    println!();
    println!("Next authentication process `cargo run --example 02_authentication`");
}
