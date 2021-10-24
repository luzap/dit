use std::fs;
use std::fs::File;
use std::io::prelude::{Write, Read};
use std::convert::AsRef;
use std::path::{Path, PathBuf};
use crate::errors::Result;

use crate::utils;

const CONFIG_FILE: &str = "config.toml";

pub fn is_config_initialized(git_dir: &dyn AsRef<Path>) -> bool {
    let path: PathBuf = [git_dir, &".dit"].iter().collect();
    path.exists()
}

// TODO This should really probably be an option
pub fn parse_config(git_dir: &dyn AsRef<Path>) -> Result<utils::Config> {
    let path: PathBuf = [git_dir, &"config.toml"].iter().collect();

    let contents = fs::read_to_string(path)?;
    
    Ok(toml::from_str::<utils::Config>(&contents)?)
}

pub fn get_keyid(git_dir: &dyn AsRef<Path>) -> Result<Vec<u8>> {
    let path: PathBuf = [git_dir, &".dit", &"keyid"].iter().collect();
    let mut file = File::open(path)?;
    let mut contents = vec![];
    let _ = file.read_to_end(&mut contents)?;

    Ok(contents)
}

pub fn write_keyid(git_dir: &dyn AsRef<Path>, keyid: &[u8]) -> Result<()> {
    let path: PathBuf = [git_dir, &".dit", &"keyid"].iter().collect();

    let mut file = File::create(path)?;
    file.write(keyid)?;

    Ok(())
}



