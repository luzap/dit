#![feature(proc_macro_hygiene, decl_macro)]

use std::collections::HashMap;
use std::sync::RwLock;

use rocket::{post, routes, State};
use rocket_contrib::json::Json;
use uuid::Uuid;

use dit::comm::{Entry, Index, Key, PartySignup};
use dit::utils::Operation;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::Parameters;

#[post("/start-operation", format = "json", data = "<request>")]
fn start_operation(db: State<RwLock<HashMap<Key, String>>>, request: Json<Operation>) {
    let op = request.0;

    let next_operation = {
        let read_db = db.read().unwrap();
        match serde_json::from_str(read_db.get("operation").unwrap()).unwrap() {
            Operation::Idle => op,
            other => other,
        }
    };
    let mut write_db = db.write().unwrap();
    write_db.insert(
        "operation".to_string(),
        serde_json::to_string(&next_operation).unwrap(),
    );
}

#[post("/get-operation", format = "json")]
fn get_operation(db: State<RwLock<HashMap<Key, String>>>) -> Json<Operation> {
    let read_db = db.read().unwrap();
    let pending_operation: Operation =
        serde_json::from_str(read_db.get("operation").unwrap()).unwrap();

    Json(pending_operation)
}

#[post("/end-operation", format = "json")]
fn end_operation(db: State<RwLock<HashMap<Key, String>>>) {
    let participants = db
        .read()
        .unwrap()
        .get("participants")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    if participants > 0 {
        let read_db = db.read().unwrap();
        let op = read_db.get("operation").unwrap();
        serde_json::from_str(&op).unwrap()
    } else {
        db.write().unwrap().insert(
            "operation".to_string(),
            serde_json::to_string(&Operation::Idle).unwrap(),
        );
    };
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
                value: v.clone().to_string(),
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
    hm.insert(entry.key.clone(), entry.value.clone());
    Json(Ok(()))
}

#[post("/signupkeygen", format = "json")]
fn signup_keygen(db_mtx: State<RwLock<HashMap<Key, String>>>) -> Json<Result<PartySignup, ()>> {
    // TODO Set this dynamically
    let params = Parameters {
        share_count: 4,
        threshold: 2,
    };
    let parties = params.share_count;

    let participants = db_mtx
        .read()
        .unwrap()
        .get("participants")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let op_id = db_mtx.read().unwrap().get("sign-uuid").unwrap().clone();

    let res = if participants < parties {
        db_mtx
            .write()
            .unwrap()
            .insert("participants".to_string(), format!("{}", participants + 1));

        Ok(PartySignup {
            number: participants + 1,
            uuid: op_id,
        })
    } else {
        Err(())
    };

    Json(res)
}

#[post("/signupsign", format = "json")]
fn signup_sign(db_mtx: State<RwLock<HashMap<Key, String>>>) -> Json<Result<PartySignup, ()>> {
    // TODO Set this from the user side
    let params = Parameters {
        share_count: 4,
        threshold: 2,
    };

    let threshold = params.threshold;
    let participants = db_mtx
        .read()
        .unwrap()
        .get("participants")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let op_id = db_mtx.read().unwrap().get("sign-uuid").unwrap().clone();

    let res = if participants < threshold + 1 {
        db_mtx
            .write()
            .unwrap()
            .insert("participants".to_string(), format!("{}", participants + 1));
        Ok(PartySignup {
            number: participants + 1,
            uuid: op_id,
        })
    } else {
        Err(())
    };

    Json(res)
}

#[post("/deregister")]
fn deregister(db: State<RwLock<HashMap<Key, String>>>) {
    let participants = db
        .read()
        .unwrap()
        .get("participants")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    db.write()
        .unwrap()
        .insert("participants".to_string(), format!("{}", participants - 1));
}

// TODO How can we best express the server's data model?
fn main() {
    let mut db: HashMap<Key, String> = HashMap::new();
    db.insert("participants".to_string(), String::from("0"));
    db.insert(
        "operation".to_string(),
        serde_json::to_string(&Operation::Idle).unwrap(),
    );
    db.insert("keygen-uuid".to_string(), Uuid::new_v4().to_string());
    db.insert("sign-uuid".to_string(), Uuid::new_v4().to_string());

    let db_mtx = RwLock::new(db);

    rocket::ignite()
        .mount(
            "/",
            routes![
                get,
                set,
                signup_keygen,
                signup_sign,
                start_operation,
                end_operation,
                get_operation,
                deregister,
            ],
        )
        .manage(db_mtx)
        .launch();
}
