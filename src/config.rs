use std::fs;
use std::fs::File;
use std::io::prelude::{Write, Read};
use std::convert::AsRef;
use std::path::{Path, PathBuf};
use crate::errors::Result;

use crate::git;
use crate::utils;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref KEY_DIR: PathBuf = Path::join(&git::GIT_DIR, ".dit");
    pub static ref LOCAL_CONFIG: PathBuf = Path::join(&git::GIT_DIR, "config.toml");
    pub static ref LAST_KEYID: PathBuf = Path::join(&KEY_DIR, "keyid");
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

pub fn get_keyid() -> Result<Vec<u8>> {
    let mut file = File::open(&LAST_KEYID.clone())?;
    let mut contents = vec![];
    let size = file.read(& mut contents)?;
    assert_ne!(size, 0);

    Ok(contents)
}

pub fn write_keyid(keyid: &[u8]) -> Result<()> {
    let mut file = File::create(&LAST_KEYID.clone())?;
    file.write(keyid)?;

    Ok(())
}



