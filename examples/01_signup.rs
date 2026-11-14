use srp6::prelude::*;

/// first part of a auth flow, the signup.
/// run with: `cargo run --example 01_signup`
fn main() {
    // this is what a user would enter in a form / terminal
    let new_username = Username::new("alice").expect("valid username");
    let user_password: ClearTextPasswordRef = "password123";

    // Reminder: choose always a Srp6_BITS type that is strong like 2048 or 4096
    let srp = Srp6_4096::default();
    let (salt, verifier) = srp.generate_new_user_secrets(&new_username, user_password);

    println!("Simulating a server and signup with user {new_username}");
    println!("{new_username}'s secrets are:");
    println!(" - Salt [s]: {salt}");
    println!(" - Password verifier [v]: {verifier}");
    println!();
    println!("This is a one time action, store the 2 in a user database");
    println!();
    println!("Next authentication process `cargo run --example 02_authentication`");
}
