
use std::convert::From;
use std::error;
use std::fmt;
use std::io;
use std::string;
use std::time;

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
            CriticalError::FileSystem(err) => {

                write!(f, "[File System]:\t{:?}",  err)
            },
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

pub fn unwrap_or_exit<T>(wrapped: Result<T>) -> T {
    match wrapped {
        Ok(val) => val,
        Err(e) => {
            println!("{}", e);
            std::process::exit(1);
        }
    }
}
