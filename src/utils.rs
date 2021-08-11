use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    pub address: String,
    pub port: u16,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub project: String,
    pub server: Server,
}

pub struct Tag {
    pub hash: String,
    pub timestamp: Duration,
}

#[derive(Serialize, Deserialize)]
pub enum Operation {
    KeyGen { leader: u32, epoch: u64 },
    Signing { leader: u32, epoch: u64, hash: String},
}

/// Get seconds since the Unix epoch
///
/// The failure condition for `SystemTime` returns a newtype wrapping `Duration`
/// to indicate why the time differencing did not work. Not sure what can be done
/// if the system clock is done without calls to external time servers, so panicking
/// on a broken system clock seems reasonable
pub fn get_current_epoch() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}

pub fn get_key_name() -> String {
    format!("{}{}", get_current_epoch().as_secs(), ".pgp")
}

pub fn read_data_from_file<'a, T: DeserializeOwned>(path: &dyn AsRef<Path>) -> T {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    serde_json::from_reader(reader).unwrap()
}
