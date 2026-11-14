pub use sha2::{digest::Update, Digest};

pub const HASH_LENGTH: usize = 512 / 8;
pub type HashFunc = sha2::Sha512;
