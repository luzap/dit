#![feature(exit_status_error)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::convert::From;
use std::error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::Path;
use std::string;
use std::time;

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
    pub timestamp: time::Duration,
}

#[derive(Serialize, Deserialize)]
pub enum Operation {
    Idle,
    KeyGen {
        max_participants: u16,
        threshold: u16,
        leader: u16,
        epoch: u64,
    },
    Signing {
        leader: u32,
        epoch: u64,
        hash: String,
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

pub fn read_data_from_file<'a, T: DeserializeOwned>(path: &dyn AsRef<Path>) -> T {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    serde_json::from_reader(reader).unwrap()
}

#[derive(Debug)]
pub struct CommandError(String);

impl From<String> for CommandError {
    fn from(error: string::String) -> Self {
        CommandError(error)
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// TODO Are these implementations necessary?
impl error::Error for CommandError {}

#[derive(Debug)]
pub enum UserError {
    TagMessage,
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserError::TagMessage => write!(f, "No tag message was provided"),
        }
    }
}

impl error::Error for UserError {}

#[derive(Debug)]
pub enum CriticalError {
    FileSystem(std::io::Error),
    Network,
    JSON(serde_json::Error),
    HTTP(reqwest::Error),
    Encoding(string::FromUtf8Error),
    Command(CommandError),
    User(UserError),
    Clock(time::SystemTimeError),
}

pub type Result<T> = std::result::Result<T, CriticalError>;

impl fmt::Display for CriticalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CriticalError::FileSystem(err) => write!(f, "[{:10?}]:\t{}", self, err),
            CriticalError::Network => write!(f, "[{:10?}]", self),
            CriticalError::JSON(err) => {
                // TODO The error context contains an `ErrorCode` enum which is *a lot* more
                // descriptive than this, and yet it does not seem to be exposed. Is there
                // anything we can do to get better error messages?
                let error_context = format!(
                    "{:?} error: line {}, col {}",
                    err.classify(),
                    err.line(),
                    err.column()
                );
                write!(f, "[{:10?}]\t{}", self, error_context)
            }
            CriticalError::HTTP(err) => write!(f, "[{:10?}]\t{}", self, err.get_ref().unwrap()),
            CriticalError::Encoding(err) => write!(f, "[{:10?}]\t{}", self, err),
            CriticalError::Command(err) => write!(f, "[{:10?}]\t{}", self, err),
            CriticalError::User(err) => write!(f, "[{:10?}]\t{}", self, err),
            CriticalError::Clock(err) => write!(f, "[{:10?}]\t{}", self, err),
        }
    }
}

impl From<io::Error> for CriticalError {
    fn from(io_error: io::Error) -> Self {
        CriticalError::FileSystem(io_error)
    }
}

impl From<serde_json::Error> for CriticalError {
    fn from(json_error: serde_json::Error) -> Self {
        CriticalError::JSON(json_error)
    }
}

impl From<reqwest::Error> for CriticalError {
    fn from(http_error: reqwest::Error) -> Self {
        CriticalError::HTTP(http_error)
    }
}

impl From<string::FromUtf8Error> for CriticalError {
    fn from(utf8_error: string::FromUtf8Error) -> Self {
        CriticalError::Encoding(utf8_error)
    }
}

impl From<time::SystemTimeError> for CriticalError {
    fn from(clock_error: time::SystemTimeError) -> Self {
        CriticalError::Clock(clock_error)
    }
}

// TODO What does this do, exactly?
impl error::Error for CriticalError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            CriticalError::FileSystem(ref err) => Some(err),
            CriticalError::Network => None,
            CriticalError::JSON(ref err) => Some(err),
            CriticalError::HTTP(ref err) => Some(err),
            CriticalError::Encoding(ref err) => Some(err),
            CriticalError::Command(ref err) => Some(err),
            CriticalError::User(ref err) => Some(err),
            CriticalError::Clock(ref err) => Some(err),
        }
    }
}
