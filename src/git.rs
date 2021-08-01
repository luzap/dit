use std::process::Command;
use std::time::Duration;
use std::path::PathBuf;
use std::fs;

// TODO This does not take into account windows \r
// (though to be fair, not sure if this compiles on windows in the first place)
fn parse_cmd_output(piped_output: &[u8]) -> String {
    let mut output = match String::from_utf8(piped_output.to_vec()) {
        Ok(output) => output,
        Err(_) => unreachable!(),
    };

    if output.ends_with('\n') {
        output.pop();
    }
    output
}

// TODO All of these functions are about the same, can we collapse them?
// TODO Handle the stderr cases if they should occur
// TODO Can we pass the commands as closures?
pub fn get_repo_root() -> String {
    let repo_root = match Command::new("git")
        .args(&["rev-parse", "--show-toplevel"])
        .output()
    {
        Ok(dir) => dir,
        Err(e) => panic!("{}", e),
    };

    if !repo_root.stdout.is_empty() {
        return parse_cmd_output(&repo_root.stdout);
    }

    String::from("")
}

pub fn get_commit_hash(commit: &str) -> String {
    let commit = match Command::new("git").args(&["rev-parse", commit]).output() {
        Ok(dir) => dir,
        Err(e) => panic!("{}", e),
    };

    if !commit.stdout.is_empty() {
        return parse_cmd_output(&commit.stdout);
    }

    String::from("")
}

pub fn get_user_name() -> String {
    let user = match Command::new("git")
        .args(&["config", "--get", "user.name"])
        .output()
    {
        Ok(dir) => dir,
        Err(e) => panic!("Git config error: {}", e),
    };

    if !user.stdout.is_empty() {
        return parse_cmd_output(&user.stdout);
    }

    String::from("")
}

pub fn get_user_email() -> String {
    let email = match Command::new("git")
        .args(&["config", "--get", "user.email"])
        .output()
    {
        Ok(dir) => dir,
        Err(e) => panic!("Git config error: {}", e),
    };

    if !email.stdout.is_empty() {
        return parse_cmd_output(&email.stdout);
    }

    String::from("")
}

// TODO This is part of GNU coreutils and therefore might
fn get_current_timezone() -> String {
    let timezone = match Command::new("date").arg("+%z").output() {
        Ok(tz) => tz,
        Err(e) => panic!("Timezone error: {}", e),
    };
    if !timezone.stdout.is_empty() {
        return parse_cmd_output(&timezone.stdout);
    }

    String::from("")
}

pub fn get_help_string() -> String {
    let help = match Command::new("git").arg("--help").output() {
        Ok(h) => h,
        Err(e) => panic!("Git error: {}", e),
    };
    if !help.stdout.is_empty() {
        return parse_cmd_output(&help.stdout);
    }

    String::from("")
}

pub fn create_tag_string(
    commit: &str,
    tag_name: &str,
    tag_message: &str,
    time: Duration,
) -> String {
    format!(
        "object {}\ntype commit \ntag {}\ntagger {} {} {} {}\n\n{}\n",
        commit,
        tag_name,
        get_user_name(),
        get_user_email(),
        time.as_secs().to_string(),
        get_current_timezone(),
        tag_message
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
pub fn create_git_tag(tag_name: &str, tag_body: &str) {
    let hash = match Command::new("git")
        .args(&["hash-object", "-t", "tag", "-w", "--stdin", tag_body])
        .output() {
            Ok(hash) => hash,
            Err(e) => panic!("Error hashing object: {}", e)
        };

    if !hash.stdout.is_empty() {
        let hash_string = parse_cmd_output(&hash.stdout);
        let mut tag_path = PathBuf::new();
        // TODO Since part of the path should be identical regardless of
        // repo, is there a better way to build the PathBuf?
        tag_path.push(get_repo_root());
        tag_path.push(".git");
        tag_path.push("refs");
        tag_path.push("tags");
        tag_path.push(tag_name);
        fs::write(tag_path, hash_string).expect("Could not write to file!");
    }
}
