use dit::app;
use dit::config;
use dit::errors;
use dit::comm::Channel;
use dit::errors::Result;

fn main() -> Result<()> {
    let app = app::build_app();

    let config = match config::parse_config(&config::LOCAL_CONFIG.clone()) {
        Some(config) => config,
        None => panic!("No config!"),
    };

    let channel = Channel::new(format!(
        "http://{}:{}",
        config.server.address, config.server.port
    ));

    let pending_operation = channel.get_current_operation();

    match app.get_matches().subcommand() {
        ("keygen", keygen_matches) => {
            if pending_operation == dit::utils::Operation::Idle {
                dit::app::leader_keygen(&mut channel, &config, keygen_matches)?;
            } else {
                println!("Pending operation: {:?}", pending_operation);
                let choice = dit::utils::get_user_choice(
                    "Participate in the pending operation?",
                    &["y", "n"],
                )?;

                if choice == 0 {
                    dit::app::participant_keygen(&mut channel, keygen_matches)?;
                }
            }
        }
        ("start-tag", tag_matches) => {
            if pending_operation == dit::utils::Operation::Idle {
                println!("Initiating tagging");

                app::tag_subcommand(config, tag_matches)?;
            } else {
                println!("Pending operation!: {:?}", pending_operation);
                // TODO Check for participation
                let choice = errors::unwrap_or_exit(dit::utils::get_user_choice(
                    "Participate in the pending operation?",
                    &["y", "n"],
                ));
                if choice == 0 {
                    app::tag_subcommand(config, tag_matches)?;

                }
            }
        }
        (other, args) => {
            println!("{:?}", args);
            app::git_passthrough(other, args)?;
        }
    };

    Ok(())
}
