use dit::app;
use dit::comm::HTTPChannel;

use dit::config;
use dit::errors;
use dit::errors::Result;

fn main() -> Result<()> {
    let app = app::build_app();


    let config = config::parse_config(&config::LOCAL_CONFIG.clone())?;

    let project = config.project.clone();

    let mut channel = HTTPChannel::new(format!(
        "http://{}:{}",
        config.server.address, config.server.port
    ), project);

    let mut reachable: bool = false;
    let mut pending_operation = dit::utils::Operation::Idle;
    match channel.get_current_operation() {
        Ok(op) => {
            reachable = true;
            pending_operation = op;
        }
        Err(_) => println!("No connection to server"),
    };

    match app.get_matches().subcommand() {
        ("keygen", keygen_matches) => {
            if reachable == true {
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
        }
        ("start-tag", tag_matches) => {
            if reachable == true {
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
        }
        (other, args) => {
            if reachable == true {
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
            }
            app::git_passthrough(other, args)?;
        }
    };

    Ok(())
}
