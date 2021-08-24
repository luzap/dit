use dit::app;
use dit::config;
use dit::errors;
use dit::utils;

fn main() {
    let app = app::build_app();

    let config = match config::parse_config(&config::LOCAL_CONFIG.clone()) {
        Some(config) => config,
        None => panic!("No config!"),
    };

    let (pending_operation, channel) = app::check_pending_operations(&config);

    // TODO Return participation bool
    let participate = match app.get_matches().subcommand() {
        ("keygen", keygen_matches) => {
            if pending_operation == dit::utils::Operation::Idle {
                println!("Initiating key generation");
                // errors::unwrap_or_exit(app::keygen_subcommand(config, keygen_matches));
                true

            } else {
                println!("Pending operation: {:?}", pending_operation);
                // TODO Check for participation
                let choice = errors::unwrap_or_exit(dit::utils::get_user_choice(
                "Participate in the pending operation?", &["Y", "n"]));

                choice == 0
            }
        }
        ("start-tag", tag_matches) => {
            if pending_operation == dit::utils::Operation::Idle {
                println!("Initiating tagging");





                // TODO Replace this with a call to the /set operation
                // errors::unwrap_or_exit(app::tag_subcommand(config, tag_matches));

                true
            } else {
                println!("Pending operation!: {:?}", pending_operation);
                // TODO Check for participation
                let choice = errors::unwrap_or_exit(dit::utils::get_user_choice(
                "Participate in the pending operation?", &["Y", "n"]));

                choice == 0
            }
        }
        (other, args) => {
            println!("Pending operation!: {:?}", pending_operation);
            errors::unwrap_or_exit(app::git_passthrough(other, args));
            true
        }
    };
    if participate {
        match pending_operation {
            dit::utils::Operation::Idle => {}
            dit::utils::Operation::KeyGen {
                participants,
                leader,
                epoch,
            } => {}
            dit::utils::Operation::SignTag {
                participants,
                threshold,
                leader,
                epoch,
                timezone,
                commit,
                hash,
            } => {}
            dit::utils::Operation::SignKey {
                participants,
                threshold,
                leader,
                epoch,
            } => {}
            dit::utils::Operation::Blame {} => {}
        }
    }
}
