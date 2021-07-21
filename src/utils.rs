use serde::{Deserialize};

#[derive(Deserialize, Debug)]
pub struct Server {
    address: String,
    port: u16,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    project: String,
    server: Server,
}
