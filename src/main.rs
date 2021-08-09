pub mod pgp;
pub mod app;
pub mod git;
pub mod channel;
pub mod utils;
pub mod config;
pub mod protocol;

fn main() {
    let app = app::build_app();
    let config = match config::find_project_config(None) {
        Some(config) => config,
        None => panic!("No config!")
    };

    if config::find_project_config(None).is_some() {
        println!("[dit] Detected project server config");
        // TODO Check pending
        // TODO If pending, launch the corresponding function without checking flags

    }

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
