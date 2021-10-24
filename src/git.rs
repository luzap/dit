#![feature(command_access)]

use std::fs;
use std::fs::File;
use std::io::prelude::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::errors::{unwrap_or_exit, CommandError, CriticalError, Result, UserError};
use crate::utils::Tag;
use std::collections::HashMap;

const GIT: &str = "git";
const TAG_MSG: &'static str = "
# Write a message for tag:
#   {}
# Lines starting with '#' will be ignored.
# Note that this is a tag signed with a threshold signature
# and might take some time to show up.";

pub struct GitEnv {
    git_config: HashMap<String, String>,
    git_dir: PathBuf,
    tag_msg_file: PathBuf,
    tag_path: PathBuf,
    tag_dir: PathBuf
}

// If this is constructed after we have already discovered that there is a config file, then
// certain operations can't fail
impl GitEnv {
    pub fn new() -> GitEnv {
        let git_dir = PathBuf::from(get_repo_root().unwrap());
        let tag_path = [".git", "refs", "tags"].iter().collect();
        GitEnv {
            git_config: unwrap_or_exit(get_git_vars()),
            git_dir,
            tag_msg_file: [".git", "TAG_EDITMSG"].iter().collect(),
            tag_path,
            tag_dir: Path::join(&git_dir, tag_path)
        }
    }
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

pub fn present_commit(commit: &str) {
    let mut show_cmd = Command::new(GIT);
    show_cmd.args(&["show", commit]);

    show_cmd.stdin(Stdio::inherit()).stdout(Stdio::inherit());
}


pub fn get_current_timezone() -> Result<String> {
    let mut tz_cmd = Command::new("date");
    tz_cmd.arg("+%z");

    let tz_data = tz_cmd.output()?;
    if !tz_data.stdout.is_empty() {
        return parse_cmd_output(&tz_data.stdout);
    } else if !tz_data.stderr.is_empty() {
        return Err(CommandError::new(
            "date +%z".to_string(),
            parse_cmd_output(&tz_data.stderr)?,
        )
        .into());
    }

    Ok(String::from("+0000"))
}

pub fn get_git_tag_message(tag: &str, env: &GitEnv) -> Result<String> {
    let editor = env.git_config.get("editor")
                .expect("Git does not expose an `editor` variable!");

    let mut editor_child = Command::new(editor);
    editor_child
        .arg(env.tag_msg_file)
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

    let mut file = File::create(env.tag_msg_file)?;
    file.write(&tag_message.as_bytes())?;

    editor_child.spawn()?.wait()?;

    let output = fs::read_to_string(env.tag_msg_file)?;
    if output.is_empty() {
        return Err(CriticalError::User(UserError::TagMessage));
    }

    let len = output.len() - TAG_MSG.len();
    if len == 0 {
        // TODO What do we
        return Err(CriticalError::User(UserError::TagMessage));
    };

    fs::remove_file(env.tag_msg_file);

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
/// echo -e "object $(git rev-parse HEAD~1)\ntype commit\ntag 0.1\ntagger Name Surname <name.surname@email.com> $(date +%s) +0100\n\nDoing a test tag" > temp.txt && gpg -bsa -o- temp.txt >> temp.txt && git hash-object -w -t tag temp.txt > .git/refs/tags/0.1
/// ```
pub fn create_git_tag(tag_name: &str, tag_body: &str, env: &GitEnv) -> Result<()> {
    let mut temp_file = File::create(".temp")?;
    temp_file.write_all(&tag_body.as_bytes())?;

    // TODO Is there any way we can get around creating a temporary file?
    // Tried to pass the buffer as-is, but everything would subsequently break
    let mut hash_cmd = Command::new(GIT);
    hash_cmd.args(&["hash-object", "-t", "tag", "-w", ".temp"]);

    let hash = hash_cmd.output()?;

    if !hash.stdout.is_empty() {
        let hash_string = parse_cmd_output(&hash.stdout)?;
        let tag_pointer = Path::join(&env.tag_path, tag_name);

        let mut tag_file = File::create(tag_pointer)?;
        tag_file.write(&hash_string.as_bytes())?;
        Ok(())
    } else {
        let command = "git hash-object -t tag -w".to_owned();
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
