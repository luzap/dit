mod protocol;
mod channel;
mod pgp;
mod app;

use std::process::{Command, Stdio};

use protocol::{dkg};
use curv::elliptic::curves::traits::*;
use curv::arithmetic::Converter;
use std::io::Write;
use std::fs;
use pgp::Packet;
use std::io::Error;

fn main() -> Result<(), Error> {
    let app = app::build_app();
    
    let matches = app.get_matches();

    match matches.subcommand() {
        ("keygen", Some(keygen_matches)) => {
            println!("Starting keygen with args {:?}", keygen_matches)
        },
        ("tag", Some(tag_matches)) => {
            println!("Starting tagging with args: {:?}", tag_matches)
        },
        (other, _) => {
            let _ = Command::new("git").arg(other)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .spawn().unwrap().wait().unwrap();

        }

    }



    /* let keys: protocol::PartyKeyPair = match dkg::distributed_keygen() {
        Ok(keys) => keys,
        Err(e) => panic!("An error occurred: {:?}", e)
    };

    let x = match keys.y_sum_s.x_coor() {
        Some(x) => x.to_bytes(),
        None => panic!("No x coordinate")
    };

    let y = match keys.y_sum_s.y_coor() {
        Some(y) => y.to_bytes(),
        None => panic!("No y coordinate")
    };

    let packet = pgp::PKPacket::new(&x, &y);
    let buffer = packet.as_bytes();
    let file = fs::OpenOptions::new()
                .write(true)
                .open("test.pgp");
    let _ = file.unwrap().write_all(&buffer); */


    Ok(())
}
