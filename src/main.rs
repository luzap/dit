use dit::app;
use dit::comm::HTTPChannel;

use dit::config;
use dit::errors;
use dit::errors::Result;

fn main() -> Result<()> {
    let app = app::build_app();

    let git_dir = match dit::git::get_repo_root() {
        Ok(dir) => dir,
        Err(_) => {
            match app.get_matches().subcommand() {
                (git_command, args) => app::git_passthrough(git_command, args)?,
            }
            return Ok(());
        }
    };
    let config = config::parse_config(&git_dir);

    // Default case: there is no config file present, and dit should fall through
    // In fact, it might be a good idea to figure out how to ensure that the
    // fallthrough mode is communicated to the user, but only once.
    if config.is_err() {
        println!("No config file present, working in git compatibility mode!");

        match app.get_matches().subcommand() {
            (git_command, args) => app::git_passthrough(git_command, args)?,
        }

        return Ok(());
    } else {
        // In this case, we actually need to consider whether it's possible to use
        // dit-specific features. For that, we need to double check how to setup
        // all of the requisite data structures, taking care to do so only when they
        // are required, to not slow execution too much.
        // TODO Does this get optimized out?
        let config = config.unwrap();

        let project = config.project.clone();

        // TODO Where do we move this out?
        let mut channel = HTTPChannel::new(
            format!("http://{}:{}", config.server.address, config.server.port),
            project,
        );

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
                    let gitenv = dit::git::GitEnv::new();

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
                                // TODO The arguments for the partipant are necessary or not?
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
    }
    Ok(())
}
