use std::time::Duration;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::Parameters;
use reqwest::Client;

mod common;
use common;

fn stub(val: usize) {
    panic!("{}", val);
}

fn main() {

    let params = Parameters { share_count: 3, threshold: 2};
    let party = params.share_count;
    let delay = Duration::from_millis(25);
    let uuid = String::from("Hello");
    let client = Client::new();

    /* common::distributed_keygen();
    common::distributed_sign(); */

}
