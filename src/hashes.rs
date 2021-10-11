
use sha1::{Digest, Sha1};

fn sha160_hash(buffer: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}

