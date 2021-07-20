use std::fs;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ffi::OsString;

use crate::utils;

const CONFIG_FILE: &str = "config.toml";
const CONFIG_DIR: &str = ".dit";

fn parse_child_output(output: &[u8]) -> String {
    let mut terminal = output.len();
    if let Some(term) = output.last() {
        if *term == b'\n' {
            terminal -= 1; 
        }
    };

    String::from_utf8((&output[..terminal]).to_vec()).unwrap()
}

fn find_file_in_path(path: &Path, filename: OsString) -> PathBuf {
    for entry in fs::read_dir(path).unwrap().flatten() {
        if entry.file_name() == filename {
            return entry.path();
        }
    }
    PathBuf::new() 
}


fn parse_config(path: &Path) -> Option<utils::Config> {
    let contents = fs::read_to_string(path).expect("No such file");

    match toml::from_str(&contents) {
        Ok(file) => Some(file),
        Err(e) => panic!("Error: {}", e)
    }
}


pub fn find_project_config(filename: Option<OsString>) -> Option<utils::Config> {
    // Check if the current path is a repo
    let repo_root = Command::new("git")
        .args(&["rev-parse", "--show-toplevel"]).output().unwrap();

    let filename = filename.unwrap_or_else(|| OsString::from(CONFIG_FILE));

    // The current directory is then a git directory
    if !repo_root.stdout.is_empty() {
        let absolute_path = parse_child_output(&repo_root.stdout);
        let repo_root = Path::new(&absolute_path);
        let config_file = &find_file_in_path(repo_root, filename);
        return parse_config(config_file.as_path());
    }

    None
}

// TODO Loof at how this might be made better
pub fn find_global_config(filename: Option<OsString>) -> Option<utils::Config> {
    // TODO Add OS-specific guards
    let home_path = match env::var("XDG_CONFIG_HOME") {
        Ok(dir) => dir,
        Err(_) => env::var("HOME").unwrap()
    };

    let config_file = filename.unwrap_or_else(|| OsString::from(CONFIG_FILE));

    let config_dir = find_file_in_path(Path::new(&home_path),
            OsString::from(CONFIG_DIR));
   
    // Checking for empty directory, even if this should not be happening
    if config_dir.components().next().is_none() {
        return None
    }
   
    let config_file = find_file_in_path(&config_dir.as_path(), config_file);
    
    if config_file.components().next().is_none() {
        return None
    }

    parse_config(&config_file.as_path())
}

// TODO Add several commands to check the server
