use clap::{crate_version, App, AppSettings, Arg, ArgMatches};
use std::process::{Command, Stdio};

use crate::channel;
use crate::git;
use crate::pgp::*;
use crate::protocol;
use crate::utils;
use crate::utils::Config;

use curv::arithmetic::Converter;
use curv::elliptic::curves::traits::*;

// TODO Make this part of the config
// TODO How do we output the correct help messages? Need to have the output
// saved somehow, but not sure how that would work, all things considered.
// Might want to use something like lazy_static!{}
const GIT: &str = "git";

pub fn build_app() -> App<'static, 'static> {
    let app = App::new("dit")
        .version(crate_version!())
        .setting(AppSettings::AllowExternalSubcommands)
        .about("A wrapper around git(1) that provides threshold signatures")
        .subcommand(
            App::new("keygen")
                .help("Signal the start of the key generation protocol")
                .arg(Arg::with_name("server").short("s"))
                .arg(Arg::with_name("keyfile").short("k").number_of_values(1)),
        )
        .subcommand(
            App::new("start-tag")
                .help("Start distributed tagging")
                .arg(Arg::with_name("message").short("m").number_of_values(1))
                .arg(Arg::with_name("tag name").required(true)),
        );
    app
}

pub fn keygen_subcommand(
    config: Config,
    args: Option<&ArgMatches<'_>>,
) -> Result<(), channel::Errors> {
    let keys = protocol::dkg::distributed_keygen(config);
    let public_key = match keys {
        Ok(k) => k,
        Err(_) => unreachable!(),
    };
    let x = public_key.y_sum_s.x_coor().unwrap().to_bytes();
    let y = public_key.y_sum_s.y_coor().unwrap().to_bytes();

    let key_file = args.unwrap().value_of("keyfile").unwrap_or("keyfile.pgp");

    let git_user = git::get_user_name();
    let git_email = git::get_user_email();
    let signing_time = utils::get_current_epoch();

    let mut message = Message::new();
    let public_key = message.new_public_key(
        PublicKey::ECDSA(CurveOID::Secp256k1, &x, &y),
        git_user,
        git_email,
        signing_time,
    );


    /* let user_id = pub_key.keyid();
    let signature =
        SignaturePacket::new(SigType::UserIDPKCert, &user_id, Some(pub_key.creation_time));
    let msg = message.get_signing_portion();
    // protocol::signing::distributed_sign()


    fs::write(key_file, message).expect("File already exists"); */

    Ok(())
}

pub fn tag_subcommand(config: Config, args: Option<ArgMatches>) -> Result<(), channel::Errors> {
    if let Some(args) = args {
        if args.is_present("sign") {
            let hash = git::get_commit_hash("HEAD");
            println!("Signing the following commit: {}", hash);
            // TODO Get key pair

            // protocol::signing::distributed_sign(hash,
        }
    }

    Ok(())
}

// TODO Move out of here
pub fn git_subcommand(subcommand: &str, args: Option<&ArgMatches>) {
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
