use std::convert::From;
use std::error::Error;
use std::fmt;
use std::io;
use std::string;
use std::time;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct CommandError {
    command: String,
    error: String,
}

impl CommandError {
    pub fn new(command: String, error: String) -> CommandError {
        CommandError { command, error }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[Command] `{}` failed with message {}",
            self.command, self.error
        )
    }
}

impl Error for CommandError {
    fn description(&self) -> &str {
        &self.error
    }

    // TODO Not entirely sure what information we can provide here
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

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

impl Error for UserError {}

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
            CriticalError::FileSystem(ref err) => {
                let description = err.to_string();
                let inner = err.into_inner();

                // TODO Anything else that can be done to simplify this?
                // Also, what can be done to make it work...
                // Rust formatting is a little bit arcane
                let root_cause: &str = if let Some(cause) = inner {
                    if let Some(error) = inner {
                        format!("caused by {}", *error)
                    } else {
                        String::from("")
                    }
                } else {
                    String::from("")
                };

                write!(f, "[File System]:\t {} {}", description, root_cause)
            }
            // TODO Right now, this error does not actually exist
            CriticalError::Network => write!(f, "[{:10?}]", self),
            CriticalError::JSON(ref err) => {
                let error_type = match err.classify() {
                    serde_json::error::Category::Io => "IO",
                    serde_json::error::Category::Syntax => "Syntax",
                    serde_json::error::Category::Data => "Data",
                    serde_json::error::Category::Eof => "End of file",
                };
                let error_context = format!(
                    "{:?} error: line {}, col {}",
                    error_type,
                    err.line(),
                    err.column()
                );
                write!(f, "[JSON]\t{}", error_context)
            }
            CriticalError::HTTP(ref err) => write!(f, "[HTTP]\t{}", err.get_ref().unwrap()),
            CriticalError::Encoding(ref err) => write!(f, "[Encoding]\t{}", err),
            CriticalError::Command(ref err) => write!(f, "[Command]\t{}", err),
            CriticalError::User(ref err) => write!(f, "[User]\t{}", err),
            CriticalError::Clock(ref err) => write!(f, "[Clock]\t{}", err),
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

impl From<CommandError> for CriticalError {
    fn from(command_error: CommandError) -> Self {
        CriticalError::Command(command_error)
    }
}

// TODO What does this do, exactly?
impl Error for CriticalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProtocolError {
    Timeout,
    Connection,
    Blame,
    Full,
}

pub fn unwrap_or_exit<T>(wrapped: Result<T>) -> T {
    match wrapped {
        Ok(val) => val,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
