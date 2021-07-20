use serde::{Deserialize};

#[derive(Deserialize, Debug)]
pub struct Server {
    address: String,
    port: u16,
}

// TODO Allow for Keybase integration here
#[derive(Deserialize, Debug)]
pub struct User {
    full_name: String,
    email: String,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    project: String,
    server: Server,
    user: Option<User>
}
