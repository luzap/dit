#![feature(proc_macro_hygiene, decl_macro)]

use std::collections::HashMap;
use std::sync::RwLock;

use rocket::{get, post, routes, State};
use rocket_contrib::json::Json;
use uuid;

mod channel;
mod utils;
use channel::*;
use utils::Operation;

// TODO The different handlers for both post and get are a bit of a hack and there's probably
// better things to do here
#[get("/get_operation", format = "json")]
fn get_state(db: State<RwLock<HashMap<Key, String>>>) -> Json<Operation> {
    let db = db.read().unwrap();
    match db.get(OP_KEY) {
        Some(current_state) => Json(serde_json::from_str(&current_state).unwrap()),
        None => unreachable!(),
    }
}

#[post("/set_operation", format = "json", data = "<request>")]
fn set_operation(db: State<RwLock<HashMap<Key, String>>>, request: Json<Operation>) {
    let read_db = db.read().unwrap();
    match read_db.get(OP_KEY) {
        // Don't allow any circumvention of the blame operation
        Some(val) => match serde_json::from_str(val).unwrap() {
            Operation::Blame {} => return,
            _ => {},
        },
        None => unreachable!()
    };

    let mut db = db.write().unwrap();
    db.insert(
        OP_KEY.to_string(),
        serde_json::to_string(&request.0).unwrap(),
    );
}

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: State<RwLock<HashMap<Key, String>>>,
    request: Json<Index>,
) -> Json<Result<Entry, ()>> {


    let index: Index = request.0;
    let hm = db_mtx.read().unwrap();
    match hm.get(&index.key) {
        Some(v) => {
            let entry = Entry {
                key: index.key,
                value: v.to_string(),
            };
            Json(Ok(entry))
        }
        None => Json(Err(())),
    }
}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: State<RwLock<HashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
    hm.insert(entry.key, entry.value);
    Json(Ok(()))
}

#[post("/blame", format = "json", data = "<request>")]
fn blame(_db_mtx: State<RwLock<HashMap<Key, String>>>, request: Json<Entry>) {
    println!("Request: {:?}", request.0);
}

#[post("/register", format = "json", data = "<request>")]
fn register(
    users_db: State<RwLock<HashMap<String, UserData>>>,
    request: Json<User>,
)  {
    let request = request.0;
    let uuid = {
        let read_db = users_db
            .read()
            .expect("Could not get a read lock on the user db");

        match read_db.get(&request.username) {
            // TODO Add some verification
            Some(user_data) => user_data.uuid.clone(),
            None => {
                uuid::Uuid::new_v4().to_string()
            }
        }
    };

    users_db.write().expect("Could not get write lock").insert(
        request.username.clone(),
        UserData {
            name: request.username,
            email: request.email,
            uuid,
        },
    );
}

struct UserData {
    name: String,
    email: String,
    uuid: String,
}

const OP_KEY: &str = "operation";

fn main() {
    let mut data: HashMap<Key, String> = HashMap::new();
    data.insert(
        OP_KEY.to_string(),
        serde_json::to_string(&Operation::Idle).unwrap(),
    );

    let data_db = RwLock::new(data);
    let users: HashMap<String, UserData> = HashMap::new();
    let users_db = RwLock::new(users);

    rocket::ignite()
        .mount("/", routes![get, set, blame, register])
        .manage(data_db)
        .manage(users_db)
        .launch();
}
