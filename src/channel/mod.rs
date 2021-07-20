use std::{time, thread};

use serde::{Serialize, Deserialize};

pub mod traits;

#[derive(Debug)]
pub enum Errors {
    Deserialization,
    Response,
    Send
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

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

pub struct Channel {
    client: reqwest::Client,
    uuid: String,
    address: String,
    retries: u8,
    retry_delay: time::Duration
}

impl Channel {
    pub fn new() -> Channel {
        Channel {
            client: reqwest::Client::new(), 
            retries: 3,
            uuid: "".to_string(),
            address: String::from("http://localhost:8000"),
            retry_delay: time::Duration::from_millis(250)
        }
    }

    pub fn check_heartbeat(&self) -> bool {
        
        for _ in 1..self.retries {
            let res = self.client
                .post(&format!("{}/{}", self.address, "heartbeat"))
                .send();
            
            if res.unwrap().status().is_success() {
                return true;
            }

            thread::sleep(self.retry_delay);
        }

        false
    }


    pub fn postb<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        for _ in 1..self.retries {
            let res = self.client
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

    pub fn broadcast(
        &self,
        party_num: u16,
        round: &str,
        data: String,
    ) -> Result<(), ()> {
        let key = format!("{}-{}-{}", party_num, round, self.uuid);
        let entry = Entry {
            key,
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
    ) -> Result<(), ()> {
        let key = format!("{}-{}-{}-{}", party_from, party_to, round, self.uuid);

        let entry = Entry {
            key,
            value: data,
        };

        let res_body = self.postb("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn poll_for_broadcasts(
        &self,
        party_num: u16,
        n: u16,
        delay: time::Duration,
        round: &str,
    ) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}", i, round, self.uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(delay);
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

    pub fn poll_for_p2p(
        &self,
        party_num: u16,
        n: u16,
        delay: time::Duration,
        round: &str,
    ) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}-{}", i, party_num, round, self.uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(delay);
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

    pub fn signup_keygen(&mut self) -> Result<u16, Errors> {
        let key = "signup-keygen".to_string();

        let res_body: String = match self.postb("signupkeygen", key) {
            Some(res) => res,
            None => return Err(Errors::Response)
        };

        match serde_json::from_str(&res_body) {
            Ok(PartySignup { uuid, number } ) => {
                self.uuid = uuid;
                Ok(number)
            },
            Err(_) => Err(Errors::Deserialization)

        }
    }

    pub fn signup_sign(&mut self) -> Result<u16, Errors> {
        let key = "signup-sign".to_string();

        let res_body: String = match self.postb("signupsign", key) {
            Some(res) => res,
            None => return Err(Errors::Response)
        };

        match serde_json::from_str(&res_body) {
            Ok(PartySignup { uuid, number } ) => {
                self.uuid = uuid;
                Ok(number)
            },
            Err(_) => Err(Errors::Deserialization)
        }
    }
}
