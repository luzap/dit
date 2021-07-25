use std::process::Command;
use std::time::Duration;

// TODO This does not take into account windows \r
// (though to be fair, not sure if this compiles on windows in the first place)
fn parse_cmd_output(piped_output: &[u8]) -> String {
    let mut output = match String::from_utf8(piped_output.to_vec()) {
        Ok(output) => output,
        Err(_) => unreachable!(),
    };

    if output.ends_with("\n") {
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

fn get_user_name() -> String {
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

fn get_user_email() -> String {
    let email = match Command::new("git")
        .args(&["config", "--get", "email.name"])
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
        Err(e) => panic!("Git error: {}", e)
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

pub fn create_git_tag(tag_body: &str) {
    Command::new("git").args(&["hash-object", "-t", "tag", "-w", "--stdin", tag_body]).output();
}
