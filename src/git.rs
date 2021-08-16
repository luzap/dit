use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::errors::{unwrap_or_exit, CriticalError, Result, UserError};
use lazy_static::lazy_static;
use std::collections::HashMap;

const TAG_MSG: &'static str = "
# Write a message for tag:
#   {}
# Lines starting with '#' will be ignored.
# Note that this is a tag signed with a threshold signature
# and might take some time to show up.";

// TODO Time to rewrite this another time
lazy_static! {
    pub static ref GIT_CONFIG: HashMap<String, String> = unwrap_or_exit(get_git_vars());
    pub static ref GIT_DIR: PathBuf = PathBuf::from(unwrap_or_exit(get_repo_root()));
    static ref TAG_MSG_FILE: PathBuf = [".git", "TAG_EDITMSG"].iter().collect();
    static ref TAG_PATH: PathBuf = [".git", "refs", "tags"].iter().collect();
    pub static ref TAG_DIR: PathBuf = Path::join(&GIT_DIR, TAG_PATH.as_path());
}

fn get_git_vars() -> Result<HashMap<String, String>> {
    let mut cfg = HashMap::new();
    let config = parse_cmd_output(&Command::new("git").args(&["config", "-l"]).output()?.stdout)?;

    for line in config.lines() {
        let split = line.split("=").collect::<Vec<&str>>();
        let key = split[0].split(".").collect::<Vec<&str>>()[1];

        cfg.insert(key.to_string(), split[1].to_string());
    }
    Ok(cfg)
}

// TODO This does not take into account windows \r
// (though to be fair, not sure if this compiles on windows in the first place)
fn parse_cmd_output(piped_output: &[u8]) -> Result<String> {
    let mut output = String::from_utf8(piped_output.to_vec())?;

    if output.ends_with('\n') {
        output.pop();
    }
    Ok(output)
}

pub fn get_repo_root() -> Result<String> {
    let repo_root = Command::new("git")
        .args(&["rev-parse", "--show-toplevel"])
        .output()?;

    parse_cmd_output(&repo_root.stdout)
}

pub fn get_commit_hash(commit: &str) -> Result<String> {
    let commit = Command::new("git").args(&["rev-parse", commit]).output()?;

    if !commit.stdout.is_empty() {
        parse_cmd_output(&commit.stdout)
    } else {
        Err(CriticalError::Command(
            parse_cmd_output(&commit.stderr)?.into(),
        ))
    }
}

pub fn get_git_config(config: &str) -> String {
    match GIT_CONFIG.get(config) {
        Some(val) => val.clone(),
        None => String::from(""),
    }
}

fn get_current_timezone() -> Result<String> {
    let timezone = Command::new("date").arg("+%z").output()?;
    if !timezone.stdout.is_empty() {
        return parse_cmd_output(&timezone.stdout);
    }

    Ok(String::from("+0000"))
}

pub fn get_git_tag_message(tag: &str) -> Result<String> {
    let mut editor_child = Command::new(get_git_config("editor"));
    let editor_child = editor_child.arg(TAG_MSG_FILE.clone().into_os_string());

    let editor_child = editor_child
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit());

    let tag_message = format!(
        "
# Write a message for tag:
#   {}
# Lines starting with '#' will be ignored.
# Note that this is a tag signed with a threshold signature
# and might take some time to show up.",
        tag
    );

    fs::write(TAG_MSG_FILE.as_path(), tag_message)?;

    editor_child.spawn()?.wait()?;

    let output = fs::read_to_string(TAG_MSG_FILE.as_path())?;
    let len = output.len() - TAG_MSG.len();
    if len == 0 {
        // TODO What do we
        return Err(CriticalError::User(UserError::TagMessage));
    };

    fs::remove_file(TAG_MSG_FILE.as_path())?;


    Ok(output
        .lines()
        .filter(|line| !line.starts_with("#"))
        .collect())
}

pub fn create_tag_string(
    commit: &str,
    tag_name: &str,
    tag_message: &str,
    time: Duration,
) -> Result<String> {
    Ok(format!(
        "object {}\ntype commit \ntag {}\ntagger {} {} {} {}\n\n{}\n",
        commit,
        tag_name,
        get_git_config("name"),
        get_git_config("email"),
        time.as_secs(),
        get_current_timezone()?,
        tag_message
    ))
}

/// Creates a tag in the local Git repository
///
/// `git hash-object -w -t tag --stdin` hashes the file and adds it to the Git
/// repository but it does not actually create a reference to it as though it were
/// a tag, which can be accomplished by writing the tag hash to `$REPO/.git/refs/tags/[TAGNAME]`.
///
/// When testing, the following command produces a functional tag:
/// ```bash
/// echo -e "object $(git rev-parse HEAD~1)\ntype commit\ntag 0.1\ntagger Lukas Zapolskas <lukas.zapolskas@gmail.com> $(date +%s) +0100\n\nDoing a test tag" > temp.txt && gpg -bsa -o- temp.txt >> temp.txt && git hash-object -w -t tag temp.txt > .git/refs/tags/0.1
/// ```
pub fn create_git_tag(tag_name: &str, tag_body: &str) -> Result<()> {
    let hash = Command::new("git")
        .args(&["hash-object", "-t", "tag", "-w", "--stdin", tag_body])
        .output()?;

    if !hash.stdout.is_empty() {
        let hash_string = parse_cmd_output(&hash.stdout)?;
        // TODO Since part of the path should be identical regardless of
        // repo, is there a better way to build the PathBuf?
        let tag_pointer = Path::join(&TAG_PATH, tag_name);

        fs::write(tag_pointer, hash_string)?;
        Ok(())
    } else {
        // TODO Make this a little better
        Err(CriticalError::Command(
            parse_cmd_output(&hash.stderr)?.into(),
        ))
    }
}
