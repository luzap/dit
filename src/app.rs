use clap::{crate_version, App, AppSettings, Arg, ArgMatches};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

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

const GIT: &str = "git";

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
        Operation::KeyGen{max_participants:_, threshold:_, leader, epoch } => {
            (leader, epoch)
        },
        _ => unreachable!()
    };

    // TODO Pass info about the number of participants here
    let public_key = dkg::distributed_keygen(&mut channel).unwrap();

    channel.deregister();
    channel.end_operation(&keygen);

    let x = public_key.y_sum_s.x_coor().unwrap().to_bytes();
    let y = public_key.y_sum_s.y_coor().unwrap().to_bytes();

    let key_file = args.unwrap().value_of("keyfile").unwrap_or("keyfile.pgp");

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
        leader
    };

    channel.start_operation(&sign_key); 
    // TODO Distribute the keys after the entire thing is done -- have the server work as PGP
    // keyserver?
    let signature = signing::distributed_sign(&mut channel, &hashable, public_key.clone()).unwrap();
    let sig_data = encode_sig_data(signature);
    message.finalize_signature(hashed, sig_data);

    message.write_to_file(&cfg::KEY_DIR.clone(), &key_file)?;
    fs::write(
        Path::join(
            &cfg::KEY_DIR.clone(),
            args.unwrap()
                .value_of("pubkey")
                .unwrap_or("public_key.json"),
        ),
        serde_json::to_string(&public_key)?,
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

pub fn git_subcommand(subcommand: &str, args: Option<&ArgMatches>) -> Result<()> {
    let mut git_child = Command::new(GIT);
    let mut git_owning = git_child.stdin(Stdio::inherit()).stdout(Stdio::inherit());

    if subcommand.is_empty() {
        git_owning = git_owning.arg("--help");
    } else {
        git_owning = git_owning.arg(subcommand);
    }

    if let Some(args) = args {
        if !args.args.is_empty() {
            let passthrough_args = &args.args[""].vals;
            git_owning = git_owning.args(passthrough_args);
        }
    }
    git_owning.spawn()?.wait()?;

    Ok(())
}
