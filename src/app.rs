use clap::{crate_version, App, AppSettings, Arg, ArgMatches};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::config as cfg;
use crate::git;
use crate::pgp::*;
use crate::protocol;
use crate::utils;
use crate::utils::{Config, Result};

const GIT: &str = "git";

// TODO Document what the commands do
pub fn build_app() -> App<'static, 'static> {
    let app = App::new("dit")
        .version(crate_version!())
        .setting(AppSettings::AllowExternalSubcommands)
        .about("A wrapper around git(1) that provides threshold signatures")
        .subcommand(
            App::new("keygen")
                .help("Signal the start of the key generation protocol")
                .arg(Arg::with_name("server").short("s"))
                .arg(Arg::with_name("keyfile").short("k").number_of_values(1))
                .arg(Arg::with_name("pubkey").short("p").number_of_values(1)),
        )
        .subcommand(
            App::new("start-tag")
                .help("Start distributed tagging")
                .arg(Arg::with_name("message").short("m").number_of_values(1))
                .arg(Arg::with_name("tag name").required(true))
                .arg(Arg::with_name("commit"))
                .arg(Arg::with_name("pubkey").short("p").number_of_values(1)),
        );
    app
}

pub fn keygen_subcommand(config: Config, args: Option<&ArgMatches<'_>>) -> Result<()> {
    let keys = protocol::dkg::distributed_keygen(&config);
    let public_key = match keys {
        Ok(k) => k,
        Err(_) => unreachable!(),
    };

    let x = public_key.y_sum_s.x_coor().unwrap().to_bytes();
    let y = public_key.y_sum_s.y_coor().unwrap().to_bytes();

    let key_file = args.unwrap().value_of("keyfile").unwrap_or("keyfile.pgp");

    let git_user = git::get_git_config("name");
    let git_email = git::get_git_config("email");
    let signing_time = utils::get_current_epoch()?;

    let mut message = Message::new();
    message.new_public_key(
        PublicKey::ECDSA(CurveOID::Secp256k1, &x, &y),
        git_user,
        git_email,
        signing_time,
    );

    let hashable = message.get_hashable();
    let hashed = message.get_sha256_hash(None);
    let hashed = &hashed[hashed.len() - 2..];

    let signature = protocol::signing::distributed_sign(&hashable, &config, public_key.clone())?;
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
        if args.is_present("sign") {
            let commit = args.value_of("commit").unwrap_or("HEAD");
            let tag = args.value_of("tag name").unwrap();
            let message = if args.is_present("message") {
                String::from(args.value_of("message").unwrap())
            } else {
                git::get_git_tag_message(tag)?
            };

            let keyfile = Path::join(
                &cfg::KEY_DIR,
                &args.value_of("keyfile").unwrap_or("public_key.json"),
            );
            let key: protocol::PartyKeyPair = utils::read_data_from_file(&keyfile);

            let hash = git::get_commit_hash(commit)?;
            let signing_time = utils::get_current_epoch()?;

            let mut tag_string = git::create_tag_string(&hash, &tag, &message, signing_time)?;

            // TODO I don't like this code block
            let mut message = Message::new();
            message.new_signature(signing_time);
            let mut hashable = tag_string.as_bytes().to_vec();
            hashable.append(&mut message.get_hashable());
            let hash = message.get_sha256_hash(Some(tag_string.as_bytes().to_vec()));

            let signature = protocol::signing::distributed_sign(&hashable, &config, key)?;
            let sig_data = encode_sig_data(signature);

            let hash = &hash[hash.len() - 2..];
            message.finalize_signature(hash, sig_data);

            // TODO Move this to a separate function
            let signature = message.get_formatted_message();
            let armor = armor_binary_output(&signature);
            tag_string.push_str(&armor);

            git::create_git_tag(tag, &tag_string);
        }
    }

    Ok(())
}

// TODO Move this to the git file
// TODO Clean this up a little
pub fn git_subcommand(subcommand: &str, args: Option<&ArgMatches>) {
    // TODO This can be refactored to separate function
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
    git_owning.spawn().unwrap().wait().unwrap();
}
