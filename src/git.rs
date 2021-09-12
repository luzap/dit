use std::fs;
use std::fs::File;
use std::io::prelude::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::errors::{unwrap_or_exit, CommandError, CriticalError, Result, UserError};
use crate::utils::Tag;
use lazy_static::lazy_static;
use std::collections::HashMap;

const GIT: &str = "git";
const TAG_MSG: &'static str = "
# Write a message for tag:
#   {}
# Lines starting with '#' will be ignored.
# Note that this is a tag signed with a threshold signature
# and might take some time to show up.";

lazy_static! {
    pub static ref GIT_CONFIG: HashMap<String, String> = unwrap_or_exit(get_git_vars());
    pub static ref GIT_DIR: PathBuf = PathBuf::from(unwrap_or_exit(get_repo_root()));
    static ref TAG_MSG_FILE: PathBuf = [".git", "TAG_EDITMSG"].iter().collect();
    static ref TAG_PATH: PathBuf = [".git", "refs", "tags"].iter().collect();
    pub static ref TAG_DIR: PathBuf = Path::join(&GIT_DIR, TAG_PATH.as_path());
}

fn get_git_vars() -> Result<HashMap<String, String>> {
    let mut cfg = HashMap::new();
    let config = parse_cmd_output(&Command::new(GIT).args(&["config", "-l"]).output()?.stdout)?;

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
    let repo_root = Command::new(GIT)
        .args(&["rev-parse", "--show-toplevel"])
        .output()?;

    parse_cmd_output(&repo_root.stdout)
}

pub fn get_commit_hash(commit: &str) -> Result<String> {
    let mut commit_cmd = Command::new(GIT);
    commit_cmd.args(&["rev-parse", commit]);

    let commit = commit_cmd.output()?;

    if !commit.stdout.is_empty() {
        parse_cmd_output(&commit.stdout)
    } else {
        let command = format!("{:?}", commit_cmd);
        let error = parse_cmd_output(&commit.stderr)?;

        Err(CommandError::new(command, error).into())
    }
}

pub fn get_git_config(config: &str) -> String {
    match GIT_CONFIG.get(config) {
        Some(val) => val.clone(),
        None => String::from(""),
    }
}

pub fn get_current_timezone() -> Result<String> {
    let timezone = Command::new("date").arg("+%z").output()?;
    if !timezone.stdout.is_empty() {
        return parse_cmd_output(&timezone.stdout);
    }

    Ok(String::from("+0000"))
}

pub fn get_git_tag_message(tag: &str) -> Result<String> {
    let mut editor_child = Command::new(get_git_config("editor"));
    editor_child
        .arg(TAG_MSG_FILE.clone().into_os_string())
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

    let mut file = File::create(TAG_MSG_FILE.as_path())?;
    file.write(&tag_message.as_bytes())?;

    editor_child.spawn()?.wait()?;

    let output = fs::read_to_string(TAG_MSG_FILE.as_path())?;
    if output.is_empty() {
        return Err(CriticalError::User(UserError::TagMessage));
    }

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

pub fn create_tag_string(tag: &Tag) -> String {
    format!(
        "object {}\ntype commit\ntag {}\ntagger {} <{}> {} {}\n\n{}\n",
        tag.commit, tag.name, tag.creator, tag.email, tag.epoch, tag.timezone, tag.message
    )
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
    let mut temp_file = File::create(".temp")?;
    temp_file.write_all(&tag_body.as_bytes())?;

    let mut hash_cmd = Command::new(GIT);
    hash_cmd.args(&["hash-object", "-t", "tag", "-w", ".temp"]);
    let hash = hash_cmd.output()?;

    if !hash.stdout.is_empty() {
        let hash_string = parse_cmd_output(&hash.stdout)?;
        let tag_pointer = Path::join(&TAG_PATH, tag_name);

        let mut tag_file = File::create(tag_pointer)?;
        tag_file.write(&hash_string.as_bytes())?;
        Ok(())
    } else {
        let command = format!("{:?}", hash_cmd);
        let error = parse_cmd_output(&hash.stderr)?;

        Err(CommandError::new(command, error).into())
    }
}

pub fn git_owning_subcommand(subcommand: &str, args: &[&str]) -> Result<()> {
    let mut git_child = Command::new(GIT);
    git_child.stdin(Stdio::inherit()).stdout(Stdio::inherit());

    // It's either this or handle possible empty subcommand at every call-site
    if subcommand.len() > 0 {
        git_child.arg(subcommand);
    }

    if args.len() > 0 {
        git_child.args(args);
    }

    git_child.spawn()?.wait()?;

    Ok(())
}
