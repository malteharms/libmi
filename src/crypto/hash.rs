use hex;
use sha2::{Sha256, Digest};


pub fn perform_hash(input: &str) -> String {
    let result: [u8; 32] = hash_with_sha256(input);
    hex::encode(result)
}

fn hash_with_sha256(input: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);

    hasher.finalize().into()
}
