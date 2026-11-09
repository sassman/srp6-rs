pub use sha1::{digest::Update, Digest};

pub const HASH_LENGTH: usize = 20;
pub type HashFunc = sha1::Sha1;
