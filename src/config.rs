use std::fs;
use std::convert::AsRef;
use std::path::{Path, PathBuf};

use crate::git;
use crate::utils;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref KEY_DIR: PathBuf = Path::join(&git::GIT_DIR, ".dit");
    pub static ref LOCAL_CONFIG: PathBuf = Path::join(&git::GIT_DIR, "config.toml");
}

pub fn parse_config(path: &dyn AsRef<Path>) -> Option<utils::Config> {
    let contents = fs::read_to_string(path).expect("No such file");

    if let Ok(mut config) = toml::from_str::<utils::Config>(&contents) {
       if config.user.is_none() {
          config.user = Some(utils::User {
                username: git::get_git_config("name"),
                email: git::get_git_config("email")
            });
        }
        Some(config)
    } else {
        None
    }
}




