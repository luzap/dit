use clap::{crate_version, App, AppSettings, Arg, ArgMatches};
use std::fs;
use std::path::Path;
use std::time::Duration;

// TODO Get rid of this -> maybe some sort of notification for the state change?
use std::thread::sleep;

use crate::comm::Channel;
use crate::comm::PartyKeyPair;
use crate::config as cfg;
use crate::dkg;
use crate::errors::Result;
use crate::git;
use crate::pgp::*;
use crate::signing;
use crate::utils;
use crate::config;
use crate::utils::{Config, Operation};

use curv::arithmetic::Converter;
use curv::elliptic::curves::traits::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;

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

/// Internal method to take care of local key generation tasks and serializing the keypair for
/// future usage
///
/// # Warning
/// Will fail on protocol, network and local file system errors
///
fn keygen_stage<P: AsRef<Path>>(channel: &mut Channel, keypair_file: P) -> Result<PartyKeyPair> {
    let keypair = dkg::distributed_keygen(channel).unwrap();

    println!("{:?}", keypair_file.as_ref());
    fs::write(keypair_file, serde_json::to_string(&keypair)?)?;

    Ok(keypair)
}

/// Internal method to marshall key signing when generation a valid PGP key. Both the leader and
/// the participants need to call this method to produce a legitimate local signed key.
///
/// Note that the current way this is structured is quite inflexible: some number of the particants
/// need to continue participating in the subsequent tag generation. In reality, this could either
/// be used to do the "offline" computation for the tag portion of the protocol, and send
/// legitimate PGP public keys to all parties (maybe the server should be a keyserver?)
///
fn keysign_stage<P: AsRef<Path>>(
    channel: &mut Channel,
    op: &Operation,
    keypair: &PartyKeyPair,
    pgp_file: P,
) -> Result<()> {
    if let Operation::SignKey {
        participants: _,
        threshold: _,
        leader,
        email,
        epoch,
    } = op
    {
        let x = keypair.y_sum_s.x_coor().unwrap().to_bytes();
        let y = keypair.y_sum_s.y_coor().unwrap().to_bytes();
        let mut message = Message::new();

        let keyid = message.new_public_key(
            PublicKey::ECDSA(CurveOID::Secp256k1, &x, &y),
            leader.clone(),
            email.clone(),
            Duration::from_secs(*epoch),
        );

        let hashable = message.get_hashable();
        let hashed = message.get_sha256_hash(None);
        let hashed = &hashed[hashed.len() - 2..];

        let signature = signing::distributed_sign(channel, &hashable, &keypair).unwrap();
        let sig_data = encode_sig_data(signature);
        message.finalize_signature(hashed, keyid.clone(), sig_data);

        message.write_to_file(pgp_file)?;
        config::write_keyid(&keyid)?;
    } else {
        println!("Started signing, with the operation: {:?}", op);
    }

    Ok(())
}

/// Initiates the key generation operation and controls its subsequent control flow
/// by sending the appropriate operations to the server.
///
/// The leader is the only party that should change the state of an existing operation
pub fn leader_keygen(
    channel: &mut Channel,
    config: &Config,
    args: Option<&ArgMatches>,
) -> Result<()> {
    // TODO Get all of these from the arguments
    let participants = 4;
    let threshold = 2;

    let (keypair_file, pgp_keyfile) = if let Some(args) = args {
        let key_base_dir = &cfg::KEY_DIR.clone();
        let pgp_keyfile = Path::join(
            &key_base_dir,
            args.value_of("keyfile").unwrap_or("keyfile.pgp"),
        );
        let keypair_file = Path::join(
            &key_base_dir,
            args.value_of("pubkey").unwrap_or("public_key.json"),
        );

        (keypair_file, pgp_keyfile)
    } else {
        let key_base_dir = &cfg::KEY_DIR.clone();

        let pgp_keyfile = Path::join(&key_base_dir, "keyfile.pgp");
        let keypair_file = Path::join(&key_base_dir, "public_key.json");
        (keypair_file, pgp_keyfile)
    };

    let user = config.user.clone().unwrap();
    let op = utils::Operation::KeyGen {
        participants,
        leader: user.username.clone(),
        email: user.email.clone(),
        epoch: utils::get_current_epoch()?.as_secs(),
    };
    channel.start_operation(&op);

    let keypair = keygen_stage(channel, keypair_file)?;
    channel.end_operation(&op);

    let op = Operation::SignKey {
        participants,
        threshold,
        leader: user.username,
        email: user.email,
        epoch: utils::get_current_epoch()?.as_secs(),
    };

    channel.start_operation(&op);

    keysign_stage(channel, &op, &keypair, pgp_keyfile)?;

    channel.end_operation(&op);

    Ok(())
}

pub fn participant_keygen(channel: &mut Channel, op: &Operation) -> Result<()> {
    // TODO Change the name of the default keyfile
    let key_base_dir = &cfg::KEY_DIR.clone();
    let pgp_keyfile = Path::join(&key_base_dir, "keyfile.pgp");

    let keypair_file = Path::join(&key_base_dir, "public_key.json");

    let keypair = keygen_stage(channel, keypair_file)?;

    // How do we do a spinlock?
    let new_op = loop {
        let new_op = channel.get_current_operation();
        if matches!(new_op, Operation::SignKey{ .. }) {
           break new_op; 
        } else {
            sleep(Duration::from_millis(250));
        }
    };
    keysign_stage(channel, &new_op, &keypair, pgp_keyfile)?;

    Ok(())
}

pub fn leader_tag(channel: &mut Channel, config: &Config, args: Option<&ArgMatches>) -> Result<()> {
    if let Some(args) = args {
        let commit = args.value_of("commit").unwrap_or("HEAD");
        let tag_name = args.value_of("tag name").unwrap();
        let message = if args.is_present("message") {
            String::from(args.value_of("message").unwrap())
        } else {
            git::get_git_tag_message(tag_name)?
        };

        let keyfile = Path::join(
            &cfg::KEY_DIR,
            &args.value_of("pubkey").unwrap_or("public_key.json"),
        );

        let hash = git::get_commit_hash(commit)?;
        let signing_time = utils::get_current_epoch()?;
        let user = config.clone().user.unwrap();

        let tag = utils::Tag {
            creator: user.username,
            email: user.email,
            epoch: signing_time.as_secs(),
            timezone: git::get_current_timezone()?,
            commit: hash.clone(),
            name: tag_name.to_string(),
            message: message.clone(),
        };

        let mut tag_string = git::create_tag_string(&tag);

        let op = Operation::SignTag {
            participants: 4,
            threshold: 2,
            tag,
        };

        channel.start_operation(&op);

        let mut message = Message::new();
        message.new_signature(signing_time);

        // TODO This API is rather nasty
        let mut hashable = tag_string.as_bytes().to_vec();
        hashable.append(&mut message.get_hashable());

        let hash = message.get_sha256_hash(Some(tag_string.as_bytes().to_vec()));
        let keyid = config::get_keyid()?;

        let signature = tag_signing_stage(channel, &hashable, keyfile)?;
        let sig_data = encode_sig_data(signature);
        let hash = &hash[hash.len() - 2..];
        message.finalize_signature(hash, keyid, sig_data);
        let signature = message.get_formatted_message();
        let armor = armor_binary_output(&signature);
        tag_string.push_str(&armor);

        git::create_git_tag(&tag_name, &tag_string)?;
    }

    Ok(())
}

fn tag_signing_stage<P: AsRef<Path>>(
    channel: &mut Channel,
    message: &[u8],
    keyfile: P,
) -> Result<SignatureRecid> {
    let keypair: PartyKeyPair = utils::read_data_from_file(&keyfile)?;
    Ok(signing::distributed_sign(channel, message, &keypair).unwrap())
}

pub fn participant_tag(channel: &mut Channel, op: &Operation) -> Result<()> {
    let (participants, threshold, tag) = match op {
            Operation::SignTag {
                participants, threshold, tag } => (participants, threshold, tag),
                _ => unimplemented!("If this occurs, this should mean that the entire system reached an error state somehow")
    };

    let mut message = Message::new();
    message.new_signature(Duration::from_secs(tag.epoch));

    let tag_string = git::create_tag_string(&tag);

    let mut hashable = tag_string.as_bytes().to_vec();
    hashable.append(&mut message.get_hashable());

    // When invoking this as a participant, the user currently does not have any way to
    // specify their keyfile, which we should add some capacity to do at some point
    let keyfile = Path::join(&cfg::KEY_DIR, "public_key.json");
    tag_signing_stage(channel, &hashable, keyfile)?;

    Ok(())
}

/// Emulate `git` behaviour by passing unrecognized subcommands directly to the system `git`
/// executable as-is.
///
/// # Warning
/// `OsString` does not always contain valid Unicode, and the conversion to Rust strings
/// may fail. Currently, `clap` takes all invalid Unicode input as erroneous, so this condition
/// should never trigger.
pub fn git_passthrough(subcommand: &str, args: Option<&ArgMatches>) -> Result<()> {
    let mut argv: Vec<&str> = Vec::new();

    if let Some(args) = args {
        let mut args: Vec<&str> = match args.values_of("") {
            Some(e) => e.collect(),
            None => vec![],
        };
        argv.append(&mut args);
    }

    // Special case of invoking `git` without subcommands or flags, which displays
    // a list of subcommands and commands to invoke to get more help
    if argv.len() == 0 {
        argv.push("--help");
    }

    git::git_owning_subcommand(subcommand, &argv)?;

    Ok(())
}
