mod common;

use serde_json;

fn main() {

    let keys = common::distributed_keygen();
    println!("Keys: {}", serde_json::to_string(&keys).unwrap());

    common::distributed_sign(String::from("Message"), keys);
}
