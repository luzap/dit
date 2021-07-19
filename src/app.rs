use clap::{App, AppSettings, Arg, ArgMatches, crate_version};
use std::process::{Command, Stdio};

// TODO Make this part of the config
// TODO How do we output the correct help messages? Need to have the output
// saved somehow, but not sure how that would work, all things considered.
// Might want to use something like lazy_static!{}
const GIT: &'static str = "git"; 



pub fn build_app() -> App<'static, 'static> {
    let app = App::new("dit")
        .version(crate_version!())
        .setting(AppSettings::AllowExternalSubcommands)
        .about(
            "A wrapper around git(1) that provides threshold signatures"
        ).subcommand(
            App::new("keygen")
                .help("Signal the start of the key generation protocol")
                .arg(
                    Arg::with_name("server")
                    .short("s")
                )
        ).subcommand(
            App::new("tag")
                .help("Start distributed tagging")
         );
    app
}

pub fn keygen_subcommand(args: Option<ArgMatches>) {
    

}

pub fn rotate_subcommand(args: Option<ArgMatches>) {


}

pub fn tag_subcommand(args: Option<ArgMatches>) {
    // TODO Check if it has to be distributed


}

pub fn get_version_message() -> String {
    String::from("")
}

pub fn get_help_message() -> String {
    String::from("")
}

pub fn git_subcommand(subcommand: &str, args: Option<&ArgMatches>) {
    let mut git_child = Command::new(GIT);
    let git_owning = git_child
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit());

    // Displays a help message
    if subcommand.is_empty() {
        git_owning.spawn().unwrap().wait().unwrap();
        return;
    }

    match args{
        Some(args) => git_owning.arg(subcommand).args(args.args[""].vals.clone()).spawn().unwrap().wait().unwrap(),
        None => git_owning.arg(subcommand).spawn().unwrap().wait().unwrap()
    };
}



