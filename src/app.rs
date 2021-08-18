use clap::{crate_version, App, AppSettings, Arg, ArgMatches};
use std::fs;
use std::path::Path;

use crate::comm::Channel;
use crate::comm::PartyKeyPair;
use crate::config as cfg;
use crate::dkg;
use crate::errors::Result;
use crate::git;
use crate::pgp::*;
use crate::signing;
use crate::utils;
use crate::utils::{Config, Operation};

use curv::arithmetic::Converter;
use curv::elliptic::curves::traits::*;

pub fn build_app() -> App<'static, 'static> {
    let app = App::new("dit")
        .version(crate_version!())
        .setting(AppSettings::AllowExternalSubcommands)
        .about("A wrapper around git(1) that provides threshold signatures")
        .subcommand(
            App::new("keygen")
                .help("Signal the start of the key generation protocol")
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .takes_value(true)
                        .help("Sets the address of the server (channel dependent)"),
                )
                .arg(
                    Arg::with_name("keyfile")
                        .short("k")
                        .number_of_values(1)
                        .help("Sets the name of the exported PGP key"),
                )
                .arg(
                    Arg::with_name("pubkey")
                        .short("p")
                        .number_of_values(1)
                        .help("Sets the name of the result of the distributed key generation"),
                ),
        )
        .subcommand(
            App::new("start-tag")
                .help("Start distributed tagging over the channel in the config")
                .arg(
                    Arg::with_name("message")
                        .short("m")
                        .number_of_values(1)
                        .help(
                            "Sets the message that will stored with the tag object.
                        If not present, the $EDITOR will be launched to compose one",
                        ),
                )
                .arg(
                    Arg::with_name("tag name")
                        .required(true)
                        .number_of_values(1)
                        .help("Sets the name of the tag"),
                )
                .arg(
                    Arg::with_name("commit")
                        .help("Sets the commit that will be tagged (defaults to current HEAD)"),
                )
                .arg(
                    Arg::with_name("pubkey")
                        .short("p")
                        .number_of_values(1)
                        .help("Sets the public key that will be used for the signing."),
                ),
        );
    app
}

// TODO Move out all of the semantically important stuff and then surround everything with guards
// that test the current pending operation
pub fn keygen_subcommand(config: Config, args: Option<&ArgMatches<'_>>) -> Result<()> {
    let mut channel = Channel::new(format!(
        "http://{}:{}",
        config.server.address, config.server.port
    ));

    let signing_time = utils::get_current_epoch()?;
    let keygen = utils::Operation::KeyGen {
        max_participants: 4,
        threshold: 2,
        leader: config.user.as_ref().unwrap().username.clone(),
        epoch: signing_time.as_secs(),
    };

    channel.start_operation(&keygen);
    let op = channel.get_current_operation();
    let (leader, epoch) = match op {
        Operation::Idle => return Ok(()),
        Operation::KeyGen {
            max_participants: _,
            threshold: _,
            leader,
            epoch,
        } => (leader, epoch),
        _ => unreachable!(),
    };

    // TODO Pass info about the number of participants here
    let keypair = dkg::distributed_keygen(&mut channel).unwrap();

    channel.deregister();
    channel.end_operation(&keygen);

    let x = keypair.y_sum_s.x_coor().unwrap().to_bytes();
    let y = keypair.y_sum_s.y_coor().unwrap().to_bytes();

    let key_file = args.unwrap().value_of("keyfile").unwrap_or("keyfile.pgp");
    let file_path = Path::join(&cfg::KEY_DIR.clone(), &key_file);

    // TODO All of a sudden, this became very ugly
    let mut message = Message::new();
    message.new_public_key(
        PublicKey::ECDSA(CurveOID::Secp256k1, &x, &y),
        config.user.as_ref().unwrap().username.clone(),
        config.user.as_ref().unwrap().email.clone(),
        signing_time,
    );

    let hashable = message.get_hashable();
    let hashed = message.get_sha256_hash(None);
    let hashed = &hashed[hashed.len() - 2..];

    let sign_key = Operation::SignKey {
        max_participants: 4,
        threshold: 2,
        epoch,
        leader,
    };

    // TODO Move this outside of the function -- creates too much coupling
    channel.start_operation(&sign_key);
    // TODO Distribute the keys after the entire thing is done -- have the server work as PGP
    // keyserver?
    let signature = signing::distributed_sign(&mut channel, &hashable, keypair.clone()).unwrap();
    let sig_data = encode_sig_data(signature);
    message.finalize_signature(hashed, sig_data);

    message.write_to_file(file_path)?;
    fs::write(
        Path::join(
            &cfg::KEY_DIR.clone(),
            args.unwrap()
                .value_of("pubkey")
                .unwrap_or("public_key.json"),
        ),
        serde_json::to_string(&keypair)?,
    )?;

    Ok(())
}

pub fn tag_subcommand(config: Config, args: Option<&ArgMatches>) -> Result<()> {
    if let Some(args) = args {
        let commit = args.value_of("commit").unwrap_or("HEAD");
        let tag = args.value_of("tag name").unwrap();
        let message = if args.is_present("message") {
            String::from(args.value_of("message").unwrap())
        } else {
            git::get_git_tag_message(tag)?
        };

        println!("{:?}", args);
        let keyfile = Path::join(
            &cfg::KEY_DIR,
            &args.value_of("pubkey").unwrap_or("public_key.json"),
        );

        let key: PartyKeyPair = utils::read_data_from_file(&keyfile)?;

        let hash = git::get_commit_hash(commit)?;
        let signing_time = utils::get_current_epoch()?;
        let mut tag_string = git::create_tag_string(&hash, &tag, &message, signing_time)?;

        let mut channel = Channel::new(format!(
            "http://{}:{}",
            config.server.address, config.server.port
        ));

        // TODO Test this
        let mut message = Message::new();
        message.new_signature(signing_time);
        let mut hashable = tag_string.as_bytes().to_vec();
        hashable.append(&mut message.get_hashable());
        let hash = message.get_sha256_hash(Some(tag_string.as_bytes().to_vec()));

        let signature = signing::distributed_sign(&mut channel, &hashable, key).unwrap();
        let sig_data = encode_sig_data(signature);

        let hash = &hash[hash.len() - 2..];
        message.finalize_signature(hash, sig_data);

        let signature = message.get_formatted_message();
        let armor = armor_binary_output(&signature);
        tag_string.push_str(&armor);

        git::create_git_tag(tag, &tag_string)?;
    }

    Ok(())
}

/// # Warning
/// `OsString` does not always contain valid Unicode, and the conversion to Rust strings
/// may fail. Right now, if any of the command-line flags passed to the executable
/// are not legitimate, we will simply remove them. 
pub fn git_passthrough(subcommand: &str, args: Option<&ArgMatches>) -> Result<()> {
    // This will not work
    let mut argv: Vec<&str> = Vec::new();
    if let Some(args) = args {
        let mut args: Vec<&str> = args.args[""].vals.iter().map(|e| {
                e.as_os_str()
                    .to_str()
            }).flatten()
            .filter(|e| e.len() != 0)
            .collect();
        argv.append(&mut args);
    }
    if argv.len() == 0 {
        argv.push("--help");
    }

    git::git_owning_subcommand(subcommand, &argv)?;

    Ok(())
}

// TODO Extract operation checking logic, which allows for the decoupling of the "leader" and
// "follower" logic
