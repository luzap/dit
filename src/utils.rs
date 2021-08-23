use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time;

use crate::errors::Result;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Server {
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub project: String,
    pub server: Server,
    pub user: Option<User>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub username: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum Operation {
    Idle,
    KeyGen {
        participants: u16,
        leader: String,
        epoch: u64,
    },
    SignTag {
        participants: u16,
        threshold: u16,
        leader: String,
        epoch: u64,
        timezone: String,
        commit: String,
        hash: String,
    },
    SignKey {
        participants: u16,
        threshold: u16,
        leader: String,
        epoch: u64,
    },
    Blame {},
}

/// Get seconds since the Unix epoch
///
/// The failure condition for `SystemTime` returns a newtype wrapping `Duration`
/// to indicate why the time differencing did not work. Not sure what can be done
/// if the system clock is done without calls to external time servers, so panicking
/// on a broken system clock seems reasonable
pub fn get_current_epoch() -> Result<time::Duration> {
    Ok(time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH)?)
}

pub fn get_key_name() -> Result<String> {
    Ok(format!("{}{}", get_current_epoch()?.as_secs(), ".pgp"))
}

pub fn read_data_from_file<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<T> {
    let file = fs::read_to_string(path)?;

    Ok(serde_json::from_str(&file)?)
}
