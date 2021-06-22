#![feature(proc_macro_hygiene, decl_macro)]

use rocket::*;
use rocket_contrib::json::Json;
use std::sync::RwLock;
use std::net::SocketAddr;
use uuid;
use serde::{Serialize, Deserialize};

const PARTY_SIZE: u16 = 4;
const THRESHOLD: u16 = 2;

#[derive(Serialize, Deserialize, Clone)]
struct User {
    uuid: uuid::Uuid,
    index: usize,
    party_size: u16,
    threshold: u16
}

impl User {
    fn new(uuid: uuid::Uuid, index: usize, party_size: u16, threshold: u16) -> User {
        User { uuid, index, party_size, threshold }

    }
    
}

#[derive(Serialize, Deserialize)]
enum RegistrationError {
    AddressInUse,
    CarryingCapacity,
    DatabaseError
}

#[get("/register", format = "json")]
fn register(users_db: State<RwLock<Vec<User>>>,
                 client: SocketAddr) ->Json<Result<User, RegistrationError>> {
    println!("{}:{}", client.ip(), client.port());
    
    let index = match users_db.read() {
        Ok(arr) => (*arr).len() + 1,
        Err(_) => return Json(Err(RegistrationError::DatabaseError)) 
    };
    
    if index > PARTY_SIZE as usize {
        return Json(Err(RegistrationError::CarryingCapacity));
    }


    let uuid = uuid::Uuid::new_v4();

    match users_db.write() {
        Ok(mut arr) => {
            let user = User::new(uuid, index, PARTY_SIZE, THRESHOLD);
            (*arr).push(user.clone());
            return Json(Ok(user));
        },
        Err(_) => return Json(Err(RegistrationError::DatabaseError))
    };
}

fn main() {
    // TODO What does this even map between?
    let users: Vec<User> = Vec::new();
    let users_db = RwLock::new(users);

    rocket::ignite()
        .mount("/", routes![register])
        .manage(users_db)
        .launch();
}

