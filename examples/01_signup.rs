use srp6::prelude::*;

fn main() {
    // this is what a user would enter in a form / terminal
    let new_username: UsernameRef = "Bob";
    let user_password: ClearTextPasswordRef = "secret-password";

    // Reminder: choose always a Srp6_BITS type that is strong like 2048 or 4096
    let srp = Srp6_2048::default();
    let (salt_s, verifier_v) = srp.generate_new_user_secrets(new_username, user_password);

    println!("Simulating a server and signup with user {}", new_username);
    println!("{}'s secrets are:", new_username);
    println!(" - Salt [s]:");
    println!("   - {}", &salt_s.to_string());
    println!(" - Password verifier [v]:");
    println!("   - {}", &verifier_v.to_string());
    println!();
    println!("This is a one time action, normally this data is stored in a user database");
    println!();
    println!("Next authentication process `cargo run --example 02_authenticate`");
}
