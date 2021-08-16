use serde::{Deserialize, Serialize};
use std::{thread, time};

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
    pub parties: u16,
    pub threshold: u16,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub email: String,
}

pub struct Channel {
    client: reqwest::Client,
    uuid: String,
    address: String,
    retries: u8,
    retry_delay: time::Duration,
}

// TODO Refactor
fn post_request<T>(
    client: &reqwest::Client,
    address: &str,
    endpoint: &str,
    body: &T,
) -> Option<String>
where
    T: serde::Serialize,
{
    let res = client
        .post(&format!("{}/{}", address, endpoint))
        .json(&body)
        .send();

    if let Ok(mut res) = res {
        return Some(res.text().unwrap());
    }
    None
}

impl Channel {
    pub fn new(user: User, server: String) -> Channel {
        let client = reqwest::Client::new();
        let retry_delay = time::Duration::from_millis(250);

        if let Some(registration) = post_request(&client, &server, "register", &user) {
            let registration: PartySignup = serde_json::from_str(&registration).unwrap();
            Channel {
                client,
                retries: 3,
                uuid: registration.uuid,
                address: server,
                retry_delay,
            }
        } else {
            Channel {
                client,
                retries: 3,
                uuid: "".to_string(),
                address: server,
                retry_delay,
            }
        }
    }

    pub fn postb<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        for _ in 1..self.retries {
            if let Some(response) = post_request(&self.client, &self.address, path, &body) {
                return Some(response);
            } else {
                thread::sleep(self.retry_delay);
            };
        }
        None
    }

    pub fn broadcast(&self, party_num: u16, round: &str, data: String) -> Result<(), ()> {
        let key = format!("{}-{}-{}", party_num, round, self.uuid);
        let entry = Entry { key, value: data };

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

        let entry = Entry { key, value: data };

        let res_body = self.postb("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
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

    pub fn signup_keygen(&mut self) -> Result<u16, Errors> {
        let key = "signup-keygen".to_string();

        let res_body: String = match self.postb("signupkeygen", key) {
            Some(res) => res,
            None => return Err(Errors::Response),
        };

        match serde_json::from_str(&res_body) {
            Ok(PartySignup { uuid, number }) => {
                self.uuid = uuid;
                Ok(number)
            }
            Err(_) => Err(Errors::Deserialization),
        }
    }

    pub fn signup_sign(&mut self) -> Result<u16, Errors> {
        let key = "signup-sign".to_string();

        let res_body: String = match self.postb("signupsign", key) {
            Some(res) => res,
            None => return Err(Errors::Response),
        };

        match serde_json::from_str(&res_body) {
            Ok(PartySignup { uuid, number }) => {
                self.uuid = uuid;
                Ok(number)
            }
            Err(_) => Err(Errors::Deserialization),
        }
    }
}
