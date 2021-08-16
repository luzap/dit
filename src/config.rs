use std::fs;
use std::convert::AsRef;
use std::path::{Path, PathBuf};


use crate::git;
use crate::utils;

use lazy_static::lazy_static;


lazy_static! {
    pub static ref KEY_DIR: PathBuf = [&git::get_repo_root(), ".dit"].iter().collect();
    pub static ref LOCAL_CONFIG: PathBuf = [&git::get_repo_root(), "config.toml"].iter().collect();
}

pub fn parse_config(path: &dyn AsRef<Path>) -> Option<utils::Config> {
    let contents = fs::read_to_string(path).expect("No such file");
    match toml::from_str(&contents) {
        Ok(file) => Some(file),
        Err(e) => panic!("Error: {}", e),
    }
}

/* pub fn find_global_config(filename: Option<String>) -> Option<utils::Config> {
    // TODO Add OS-specific guards
    let home_path = match env::var("XDG_CONFIG_HOME") {
        Ok(dir) => dir,
        Err(_) => env::var("HOME").unwrap(),
    };

    let config_file = filename.unwrap_or_else(|| String::from(CONFIG_FILE));
    



    let config_dir = find_file_in_path(Path::new(&home_path), OsString::from(CONFIG_DIR));
    // Checking for empty directory, even if this should not be happening
    if config_dir.components().next().is_none() {
        return None;
    }
    let config_file = find_file_in_path(config_dir, config_file);
    if config_file.components().next().is_none() {
        return None;
    }

    parse_config(config_file.as_path())
} */

