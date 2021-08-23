#![feature(proc_macro_hygiene, decl_macro)]

use std::collections::HashMap;
use std::sync::{atomic::AtomicUsize, Arc, RwLock};

use rocket::{post, routes, State};
use rocket_contrib::json::Json;
use uuid::Uuid;

// TODO Move these to a separate crate
use dit::comm::{Entry, Index, Key, PartySignup};
use dit::utils::Operation;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::Parameters;

// TODO Now we need to send the project name with every message
// TODO Start doing error checks on the locks
// TODO Start handling server errors

#[post("/start-operation", format = "json", data = "<request>")]
fn start_operation(db: State<RwLock<HashMap<String, Project>>>, request: Json<Operation>) {
    // TODO Remove this
    let project_name = "project".to_owned();

    let (operation, exists) = {
        let read_db = db.read().unwrap();
        match read_db.get(&project_name) {
            Some(project) => ((*project).operation.clone(), true),
            None => (Arc::new(Operation::Idle), false),
        }
    };

    // We don't want to handle interrupted operations at this point
    let new_operation = request.0;

    let new_operation = match *operation {
        Operation::Idle => Arc::new(new_operation),
        _ => operation,
    };

    if exists != true {
        let mut write_db = db.write().unwrap();
        write_db.insert(
            project_name.clone(),
            Project {
                name: project_name,
                operation: new_operation,
                active_participants: Arc::new(AtomicUsize::new(0)),
                keygen_identifier: Uuid::new_v4().to_string(),
                sign_identifier: Uuid::new_v4().to_string(),
                cache: RwLock::new(HashMap::new()),
            },
        );
    } else {
        let mut write_db = db.write().unwrap();
        match write_db.get_mut(&project_name) {
            Some(project) => project.operation = new_operation,
            None => unreachable!(),
        }
    };
}

#[post("/get-operation", format = "json")]
fn get_operation(db: State<RwLock<HashMap<String, Project>>>) -> Json<Operation> {
    let project_name = "project".to_owned();

    let read_db = db.read().unwrap();
    let pending_operation: Operation = (*read_db.get(&project_name).unwrap().operation).clone();

    Json(pending_operation)
}

#[post("/end-operation", format = "json")]
fn end_operation(db: State<RwLock<HashMap<String, Project>>>) {
    let project_name = "project".to_owned();

    let participants = db
        .read()
        .unwrap()
        .get(&project_name)
        .unwrap()
        .active_participants.clone();

    // TODO How do we make this work, again?
    if (*participants).into_inner() < 0 {
        db.write().unwrap().get_mut(&project_name).unwrap().
            operation = Arc::new(Operation::Idle);
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

struct Project {
    name: String,
    operation: Arc<Operation>,
    active_participants: Arc<AtomicUsize>,
    keygen_identifier: String,
    sign_identifier: String,
    cache: RwLock<HashMap<Key, String>>,
}

fn main() {
    let projects: HashMap<String, Project> = HashMap::with_capacity(1);
    let db_mtx = RwLock::new(projects);

    // TODO Add logging and TLS
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
