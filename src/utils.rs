use std::time::Duration;
use serde::{Deserialize, Serialize};

// TODO Implement conversion to string
// TODO Start using the project data in the server

#[derive(Deserialize, Debug)]
pub struct Server {
    pub address: String,
    pub port: u16,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub project: String,
    pub server: Server,
}

pub struct Tag {
    pub hash: String,
    pub timestamp: Duration
}

#[derive(Serialize, Deserialize)]
pub enum Operation {
    KeyGen,
    Signing
}
