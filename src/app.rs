use clap::{App, AppSettings, Arg, ArgMatches};
use std::process::{Command, Stdio};

// TODO Make this part of the config
const GIT: &'static str = "git"; 

pub fn build_app() -> App<'static, 'static> {
    let app = App::new("dit")
        .version("0.0.3")
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
         ).arg(
            Arg::with_name("version")
                .short("v")
            );
    app
}

pub fn keygen_subcommand<'a>(subcommand: &'a str, args: Option<ArgMatches<'a>>) {

}

pub fn sign_subcommand<'a>(subcommand: &'a str, args: Option<ArgMatches<'a>>) {


}

pub fn version() {

}

pub fn git_subcommand<'a>(subcommand: &'a str, args: Option<&ArgMatches<'a>>) {
    let mut git_child = Command::new(GIT);
    let git_owning = git_child
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit());

    // Displays a help message
    if subcommand == "" {
        println!("This triggered");
        git_owning.spawn().unwrap().wait().unwrap();
        return;
    }

    match args{
        Some(args) => git_owning.arg(subcommand).args(args.args[""].vals.clone()).spawn().unwrap().wait().unwrap(),
        None => git_owning.arg(subcommand).spawn().unwrap().wait().unwrap()
    };
}



