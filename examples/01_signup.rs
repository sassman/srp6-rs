use srp6::*;

fn main() {
    // this is what a user would enter in a form / terminal
    let new_username: UsernameRef = "Bob";
    let user_password: &ClearTextPassword = "secret-password";

    // Reminder: choose always a Srp6_BITS type that is strong like 2048 or 4096
    let srp = Srp6_2048::default();
    let (salt_s, verifier_v) = srp.generate_new_user_secrets(new_username, user_password);
    assert_eq!(salt_s.num_bytes(), 2048 / 8);
    assert_eq!(verifier_v.num_bytes(), 2048 / 8);

    println!("Simulating a server and signup with user {}", new_username);
    println!("{}'s secrets are:", new_username);
    println!(" - Salt              [s] = {:?}", &salt_s);
    println!(" - Password verifier [v] = {:?}", &verifier_v);
    println!("This is a one time action, normally this data is stored in a user database");
    println!();
    println!("Next authentication process `cargo run --example 02_authenticate`");
}
