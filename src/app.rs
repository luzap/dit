use clap::{crate_version, App, AppSettings, Arg, ArgMatches};
use std::process::{Command, Stdio};
use std::fs;

use crate::channel;
use crate::protocol;
use crate::utils::Config;
use crate::git;
use crate::pgp;
use crate::pgp::Packet;

use curv::elliptic::curves::traits::*;
use curv::arithmetic::Converter;

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
                .arg(Arg::with_name("keyfile").short("k").number_of_values(1))
        )
        .subcommand(
            App::new("start-tag").help("Start distributed tagging")
            .arg(Arg::with_name("message").short("m").number_of_values(1))
            .arg(Arg::with_name("tag name").required(true))
        );
    app
}

pub fn keygen_subcommand(
    config: Config,
    args: Option<&ArgMatches<'_>>,
) -> Result<(), channel::Errors> {
    // TODO Get configs
    // TODO Where are we storing these guys
    // TODO How do we signal others that this is about to happen
    let keys = protocol::dkg::distributed_keygen(config);
    let public_key = match keys {
        Ok(k) => k,
        Err(_) => unreachable!()
    };
    
    let x = public_key.y_sum_s.x_coor().unwrap().to_bytes();
    let y = public_key.y_sum_s.y_coor().unwrap().to_bytes();

    let key_file = args.unwrap().value_of("keyfile").unwrap_or("keyfile.pgp");
    let pub_key = pgp::PKPacket::new(pgp::PublicKey::ECDSA(pgp::CurveOID::Secp256k1, &x, &y), None);
    let user_packet = pgp::UserID {
        user: git::get_user_name(),
        email: git::get_user_email()
    };
    let mut message = pub_key.as_bytes();
    message.extend(user_packet.as_bytes());
        
    fs::write(key_file, message).expect("File already exists");

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
    let mut git_owning = git_child
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit());

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
