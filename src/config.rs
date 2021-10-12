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
    pub static ref INITIALIZED: bool = KEY_DIR.exists();
    pub static ref LOCAL_CONFIG: PathBuf = Path::join(&git::GIT_DIR, "config.toml");
    pub static ref LAST_KEYID: PathBuf = Path::join(&KEY_DIR, "keyid");
}

pub fn parse_config(path: &dyn AsRef<Path>) -> Result<utils::Config> {
    let contents = fs::read_to_string(path).expect("No such file");
    
    let partial_config = toml::from_str::<utils::Config>(&contents);
    match partial_config {
        Ok(mut cfg) => {
            if cfg.user.is_none() {
                cfg.user = Some(utils::User {
                    username: git::get_git_config("name"),
                    email: git::get_git_config("email")
                });
            }
            Ok(cfg)
        }
        Err(e) => Err(e.into())
    }
}

pub fn get_keyid() -> Result<Vec<u8>> {
    let mut file = File::open(&LAST_KEYID.clone())?;
    let mut contents = vec![];
    let _ = file.read_to_end(&mut contents)?;

    Ok(contents)
}

pub fn write_keyid(keyid: &[u8]) -> Result<()> {

    let mut file = File::create(&LAST_KEYID.clone())?;
    file.write(keyid)?;

    Ok(())
}



