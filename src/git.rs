use std::process::Command;
use std::time::Duration;


// TODO This does not take into account windows \r
// (though to be fair, not sure if this compiles on windows in the first place)
fn parse_git_output(piped_output: &[u8]) -> String {
    let mut output = match String::from_utf8(piped_output.to_vec()) {
        Ok(output) => output,
        Err(_) => unreachable!()
    };

    if output.ends_with("\n") {
        output.pop();
    }
    output 
}

// TODO All of these functions are about the same, can we collapse them?
// TODO What are we returning here
pub fn get_repo_root<'a>() -> String {
    let repo_root = match Command::new("git")
        .args(&["rev-parse", "--show-toplevel"]).output() {

       Ok(dir) => dir,
       Err(e) => panic!("{}", e)
    };

    if !repo_root.stdout.is_empty() {
        return parse_git_output(&repo_root.stdout);
    }

    String::from("")
}

pub fn get_commit_hash(commit: &str) -> String {
    let commit = match Command::new("git")
        .args(&["rev-parse", commit]).output() {
            Ok(dir) => dir,
            Err(e) => panic!("{}", e)
        };

    if !commit.stdout.is_empty() {
        return parse_git_output(&commit.stdout);
    }

    String::from("")
}

fn get_user_name() -> String {
    let user = match Command::new("git")
        .args(&["config", "--get", "user.name"])
        .output() {
            Ok(dir) => dir,
            Err(e) => panic!("{}", e)
        };

    if !user.stdout.is_empty() {
        return parse_git_output(&user.stdout);
    }

    String::from("")
}

fn get_user_email() -> String {
    let email = match Command::new("git")
        .args(&["config", "--get", "email.name"])
        .output() {
            Ok(dir) => dir,
            Err(e) => panic!("{}", e)
        };

    if !email.stdout.is_empty() {
        return parse_git_output(&email.stdout);
    }

    String::from("")

}

pub fn create_tag_string(commit: &str, tag_name: &str, tag_message: &str, time: Duration) -> String {
    format!("object {}\ntype commit \ntag {}\ntagger {} {} {}\n\n{}", 
        commit, tag_name, get_user_name(), get_user_email(), time.as_secs().to_string(),
        tag_message)
}

