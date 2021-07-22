mod pgp;
mod app;
mod git;
mod utils;
mod config;
mod channel;
mod protocol;


// TODO Do better handling of the config options
fn main() {
    let app = app::build_app();
    let config = match config::find_project_config(None) {
        Some(config) => config,
        None => panic!("No config!")
    };
    println!("HEAD is at {}", git::get_commit_hash("HEAD"));


    if config::find_project_config(None).is_some() {
        println!("Detected project server config");
    }

    match app.get_matches().subcommand() {
        ("keygen", keygen_matches) => {
            println!("Starting keygen with args {:?}", keygen_matches);
            let keygen_result = app::keygen_subcommand(config, keygen_matches);
        },
        ("tag", tag_matches) => {
            println!("Starting tagging with args: {:?}", tag_matches);
            // let tag_result = app::tag_subcommand(config, tag_matches);
        },
        (other, args) => {
            app::git_subcommand(other, args);
        }
    };

}
