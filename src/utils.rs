use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Display;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::time;

use crate::errors::Result;
pub const DIT_LOG: &str = "\x1B[31m[dit]\x1B[0m\t";
/// Executing commands instantly when the operation is done does not allow the 
/// user to read through the results
pub const USER_SLEEP: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Server {
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub project: String,
    pub server: Server,
    pub participants: u16,
    pub threshold: u16,
    pub user: Option<User>
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
        email: String,
        epoch: u64,
    },
    // TODO Might be best to encapsulate some of this to a dedicated structure, to avoid the
    // clutter
    SignTag {
        participants: u16,
        threshold: u16,
        tag: Tag,
    },
    SignKey {
        participants: u16,
        threshold: u16,
        leader: String,
        email: String,
        epoch: u64,
    },
    Blame {},
}

impl Display for Operation {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Operation::Idle => write!(fmt, "Currently idle"),
            Operation::KeyGen {
                participants,
                leader,
                email,
                epoch,
            } => write!(
                fmt,
                "{} <{}> started key generation at {} with {} participants",
                leader, email, epoch, participants
            ),
            Operation::SignTag {
                participants,
                threshold,
                tag,
            } => write!(
                fmt,
                "Signing tag with a {}-{} threshold:\n{}",
                participants, threshold, tag
            ),
            Operation::SignKey {
                participants,
                threshold,
                leader,
                email,
                epoch,
            } => write!(
                fmt,
                "{} <{}> started signing the key with a {}-{} threshold at {}",
                leader, email, participants, threshold, epoch
            ),
            Operation::Blame {} => write!(fmt, "Protocol has been terminated"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
pub struct Tag {
    pub creator: String,
    pub email: String,
    pub epoch: u64,
    // TODO Technically this could be an integer with some string conversion
    pub timezone: String,
    pub name: String,
    pub commit: String,
    pub message: String,
}

impl Display for Tag {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            fmt,
            "tag {}\ncreator {} <{}>\nepoch {} {}\n\n{}",
            self.commit, self.creator, self.email, self.epoch, self.timezone, self.message
        )
    }
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

pub fn get_user_choice(prompt: &str, choices: &[&str]) -> Result<usize> {
    let mut input = String::with_capacity(choices[0].len());
    // Indicating that the default choice is the first one
    let default_choice = format!("{}/{}", choices[0], choices[1..].join("/"));

    loop {
        input.clear();
        print!("{} [{}]: ", prompt, default_choice);
        io::stdout().flush()?;
        // Note that this includes the newline delimiter as the final character, so we're going to
        // ignore it
        let len = io::stdin().read_line(&mut input)? - 1;

        if len == 0 {
            return Ok(0);
        };

        let input = &input[..len];

        if choices.contains(&input) {
            return Ok(choices.iter().position(|e| e == &input).unwrap());
        }
    }
}

