pub mod pgp;
pub mod app;
pub mod git;
pub mod channel;
pub mod utils;
pub mod config;
pub mod protocol;


fn main() {
    let app = app::build_app();

    let config = match config::parse_config(&config::LOCAL_CONFIG.clone()) {
        Some(config) => config,
        None => panic!("No config!")
    };


    match app.get_matches().subcommand() {
        ("keygen", keygen_matches) => {
            let keygen_result = app::keygen_subcommand(config, keygen_matches);
            // TODO Save the result in the correct folder
            // TODO Let's ignore user stuff for the moment

        },
        ("start-tag", tag_matches) => {
            let tag_result = app::tag_subcommand(config, tag_matches);
        },
        (other, args) => {
            app::git_subcommand(other, args);
        }
    };

}
