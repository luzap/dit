use std::time::{Duration, SystemTime};
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

/// Get seconds since the Unix epoch
///
/// The failure condition for `SystemTime` returns a newtype wrapping `Duration`
/// to indicate why the time differencing did not work. Not sure what can be done 
/// if the system clock is done without calls to external time servers, so panicking
/// on a broken system clock seems reasonable
pub fn get_current_epoch() -> Duration {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()
}
