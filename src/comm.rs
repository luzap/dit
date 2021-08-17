use serde::{Deserialize, Serialize};
use std::{thread, time};

use crate::errors::Result as LocalResult;
use crate::utils::Operation;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::GE;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{Keys, SharedKeys};
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS<GE>>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_N_tilde_vec_s: Vec<DLogStatement>,
}

pub type Key = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

pub struct Channel {
    client: reqwest::Client,
    uuid: String,
    address: String,
    retries: u8,
    retry_delay: time::Duration,
}

impl Channel {
    pub fn new(server: String) -> Channel {
        Channel {
            client: reqwest::Client::new(),
            retries: 3,
            uuid: "".to_string(),
            address: String::from(server),
            retry_delay: time::Duration::from_millis(250),
        }
    }

    pub fn postb<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        for _i in 1..self.retries {
            let res = self
                .client
                .post(&format!("{}/{}", self.address, path))
                .json(&body)
                .send();

            if let Ok(mut res) = res {
                return Some(res.text().unwrap());
            }
            thread::sleep(self.retry_delay);
        }
        None
    }

    pub fn broadcast(&self, party_num: u16, round: &str, data: String) -> Result<(), ()> {
        let key = format!("{}-{}-{}", party_num, round, self.uuid);
        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = self.postb("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn sendp2p(
        &self,
        party_from: u16,
        party_to: u16,
        round: &str,
        data: String,
    ) -> LocalResult<()> {
        let key = format!("{}-{}-{}-{}", party_from, party_to, round, self.uuid);

        let entry = Entry { key, value: data };
        // TODO Do some more checking for this
        let res_body = self.postb("set", entry).unwrap();
        let res: Result<(), ()> = serde_json::from_str(&res_body).unwrap();

        if let Ok(_) = res {
            Ok(())
        } else {
            panic!("Could not set value!");
        }
    }

    pub fn poll_for_broadcasts(&self, party_num: u16, n: u16, round: &str) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}", i, round, self.uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(time::Duration::from_millis(25));
                    let res_body = self.postb("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if let Ok(answer) = answer {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

    pub fn poll_for_p2p(&self, party_num: u16, n: u16, round: &str) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}-{}", i, party_num, round, self.uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(time::Duration::from_millis(25));
                    let res_body = self.postb("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if let Ok(answer) = answer {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

    pub fn start_operation(&self, op: &Operation) {
        self.postb("start-operation", op);
    }

    pub fn end_operation(&self, op: &Operation) {
        self.postb("end-operation", op);
    }

    pub fn get_current_operation(&self) -> Operation {
        serde_json::from_str(&self.postb("get-operation", 0).unwrap()).unwrap()
    }

    pub fn signup_keygen(&mut self) -> Result<u16, ()> {
        let key = "signup-keygen".to_string();

        let res_body: String = self.postb("signupkeygen", key).unwrap();
        let res_body: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();

        if let Ok(res) = res_body {
            self.uuid = res.uuid;
            Ok(res.number)
        } else {
            panic!("Couldn't register!");
        }
    }

    pub fn signup_sign(&mut self) -> Result<u16, ()> {
        let key = "signup-sign".to_string();

        let res_body: String = self.postb("signupkeygen", key).unwrap();
        let res_body: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
        if let Ok(res) = res_body {
            self.uuid = res.uuid;

            Ok(res.number)
        } else {
            // TODO Something about this seems a little wrong
            panic!("Couldn't register!");
        }
    }

    pub fn deregister(&self) {
        self.postb("deregister", 0);
    }

}
