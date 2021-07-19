use clap::{App, AppSettings};

pub fn build_app() -> App<'static, 'static> {
    let app = App::new("dit")
        .version("0.0.3")
        .setting(AppSettings::AllowExternalSubcommands)
        .about(
            "A wrapper around git(1) that provides threshold signatures"
        ).subcommand(
            App::new("keygen")
                .help("Signal the start of the key generation protocol")
        ).subcommand(
            App::new("tag")
                .help("Start distributed tagging")
         );


    app
}


