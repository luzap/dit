use dit::app;
use dit::comm::Channel;
use dit::config;
use dit::errors;
use dit::errors::Result;

fn main() -> Result<()> {
    let app = app::build_app();

    let config = match config::parse_config(&config::LOCAL_CONFIG.clone()) {
        Some(config) => config,
        None => panic!("No config!"),
    };

    let mut channel = Channel::new(format!(
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
                    dit::app::participant_keygen(&mut channel, &pending_operation)?;
                }
            }
        }
        ("start-tag", tag_matches) => {
            if pending_operation == dit::utils::Operation::Idle {
                println!("Initiating tagging");

                app::leader_tag(&mut channel, &config, tag_matches)?;
            } else {
                println!("Pending operation!: {:?}", pending_operation);

                if errors::unwrap_or_exit(dit::utils::get_user_choice(
                    "Participate in the pending operation?",
                    &["y", "n"],
                )) == 0
                {
                    app::participant_tag(&mut channel, &pending_operation)?;
                }
            }
        }
        (other, args) => {
            if pending_operation != dit::utils::Operation::Idle {
                if errors::unwrap_or_exit(dit::utils::get_user_choice(
                    "Participate in the pending operation?",
                    &["y", "n"],
                )) == 0
                {
                    match pending_operation {
                        // TODO The argument is not quite correct and should be changed
                        dit::utils::Operation::KeyGen { .. } => {
                            app::participant_keygen(&mut channel, &pending_operation)?
                        }
                        dit::utils::Operation::SignTag { .. } => {
                            app::participant_tag(&mut channel, &pending_operation)?
                        }
                        dit::utils::Operation::Blame {} => unimplemented!(),
                        _ => unreachable!(),
                    };
                }
            }
            app::git_passthrough(other, args)?;
        }
    };

    Ok(())
}
