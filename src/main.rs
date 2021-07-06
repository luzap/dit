mod protocol;
mod channel;
mod pgp;

use protocol::{dkg, signing};


fn main() {

    let a: [u8; 6] = [1, 2, 3, 4, 5, 6];
    let _ = pgp::data_to_radix64(&a);
    let keys: protocol::PartyKeyPair = match dkg::distributed_keygen() {
        Ok(keys) => keys,
        Err(e) => panic!("An error occurred: {:?}", e)
    };

    let _ = signing::distributed_sign(String::from("Message"), keys);
    
}
