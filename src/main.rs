mod protocol;
mod pgp;

fn main() {

    let keys: protocol::PartyKeyPair = match protocol::distributed_keygen() {
        Ok(keys) => keys,
        Err(e) => panic!("An error occurred: {:?}", e)
    };

    let _ = protocol::distributed_sign(String::from("Message"), keys);
    
}
