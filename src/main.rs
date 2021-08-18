use dit::app;
use dit::config;
use dit::errors;

fn main() {
    let app = app::build_app();

    let config = match config::parse_config(&config::LOCAL_CONFIG.clone()) {
        Some(config) => config,
        None => panic!("No config!"),
    };

    match app.get_matches().subcommand() {
        ("keygen", keygen_matches) => {
            errors::unwrap_or_exit(app::keygen_subcommand(config, keygen_matches));
        }
        ("start-tag", tag_matches) => {
            errors::unwrap_or_exit(app::tag_subcommand(config, tag_matches));
        }
        (other, args) => {
            errors::unwrap_or_exit(app::git_passthrough(other, args));
        }
    };
}
