// Part of the code here has been taken from

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{thread, time};

use crate::errors::ProtocolError;
use crate::errors::Result as LocalResult;
use crate::utils::Operation;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::GE;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{Keys, SharedKeys};
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int: u16,
    pub vss_scheme_vec: Vec<VerifiableSS<GE>>,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum: GE,
    pub h1_h2_N_tilde_vec: Vec<DLogStatement>,
}

pub type Key = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
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

pub trait Channel: Serialize + DeserializeOwned {
    fn send_p2p(&self) -> Result<(), ProtocolError>;
    fn send_broadcast(&self) -> Result<(), ProtocolError>;
    fn start_operation(&self) -> Result<(), ProtocolError>;
    fn end_operation(&self) -> Result<(), ProtocolError>;
    fn check_operation(&self) -> Result<Operation, ProtocolError>;
    fn blame(&self) -> Result<(), ProtocolError>;
}

pub struct HTTPChannel {
    client: reqwest::Client,
    address: String,
    retries: u8,
    retry_delay: time::Duration,
    project: String
}

impl HTTPChannel {
    pub fn new(server: String, project: String) -> HTTPChannel {
        HTTPChannel {
            client: reqwest::Client::new(),
            retries: 3,
            address: String::from(server),
            retry_delay: time::Duration::from_millis(250),
            project
        }
    }

    fn postb<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        let msg = (self.project.clone(), body);

        for _ in 1..self.retries {
            let res = self
                .client
                .post(&format!("{}/{}", self.address, path))
                .json(&msg)
                .send();

            if let Ok(mut res) = res {
                return Some(res.text().unwrap());
            }
            thread::sleep(self.retry_delay);
        }
        None
    }

    pub fn broadcast(&self, party_num: u16, round: &str, data: String) -> Result<(), ()> {
        // TODO Probably need more of these
        let key = format!("{}-{}", party_num, round);
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
        let key = format!("{}-{}-{}", party_from, party_to, round);

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
                let key = format!("{}-{}", i, round);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(self.retry_delay);
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
                let key = format!("{}-{}-{}", i, party_num, round);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(self.retry_delay);
                    let res_body = &self.postb("get", index.clone()).unwrap();

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

    pub fn get_current_operation(&self) -> Result<Operation, ProtocolError> {
        match &self.postb("get-operation", 0) {
            Some(res) => Ok(serde_json::from_str(&res).unwrap()),
            None => Err(ProtocolError::Connection)
        }
    }

    pub fn signup_keygen(&self) -> Result<u16, ProtocolError> {
        let key = "signup-keygen".to_string();

        let res_body: String = self.postb("signupkeygen", key).unwrap();
        let res_body: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();

        if let Ok(res) = res_body {
            Ok(res.number)
        } else {
            Err(ProtocolError::Full)
        }
    }

    pub fn signup_sign(&self) -> Result<u16, ProtocolError> {
        let key = "signup-sign".to_string();

        let res_body: String = self.postb("signupsign", key).unwrap();

        let res_body: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();

        if let Ok(res) = res_body {
            Ok(res.number)
        } else {
            Err(ProtocolError::Full)
        }
    }

    pub fn signout(&self) -> Result<(), ProtocolError> {
        let key = "sign".to_owned();

        let res_body: String = self.postb("signoutsign", key).unwrap();
        let res_body: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();

        if let Ok(_) = res_body {
            Ok(())
        } else {
            Err(ProtocolError::Full)
        }
    }

    pub fn clear(&self) {
        self.postb("clear", 0);
    }

}
