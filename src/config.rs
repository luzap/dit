use std::fs;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ffi::OsString;
use serde::{Deserialize};

#[derive(Deserialize, Debug)]
pub struct Server {
    address: String,
    port: u16,
}

// TODO Allow for Keybase integration here
#[derive(Deserialize, Debug)]
pub struct User {
    full_name: String,
    email: String,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    project: String,
    server: Server,
    user: Option<User>
}

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


fn parse_config(path: &Path) -> Option<Config> {
    let contents = fs::read_to_string(path).expect("No such file");

    match toml::from_str(&contents) {
        Ok(file) => Some(file),
        Err(e) => panic!("Error: {}", e)
    }
}


pub fn find_project_config(filename: Option<OsString>) -> Option<Config> {
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


pub fn find_global_config(filename: Option<OsString>) {
   let home_dir = Path::new(&env::var("XDG_CONFIG_HOME").unwrap_or_else(
        |_| env::var("HOME").unwrap()
    ));
    let filename = filename.unwrap_or_else(|| OsString::from(CONFIG_FILE));
}

pub fn create_user_config() {

}

pub fn create_server_config() {

}


