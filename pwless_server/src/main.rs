#[macro_use]
extern crate warp;
#[macro_use]
extern crate serde_derive;
use curve25519_dalek::ristretto::{RistrettoPoint};
use std::sync::{Arc, Mutex};
use warp::{http::StatusCode, Filter};
use pwless::UserDB;



const domain: &'static str = "rust.meetup";

type Db = Arc<Mutex<UserDB>>;

#[derive(Deserialize, Serialize, Debug)]
struct Signup {
    username: String,
    key: RistrettoPoint,
}

#[tokio::main]
async fn main() {
    let json_body = warp::body::json();
    let user_db = Arc::new(Mutex::new(UserDB::default()));
    let db = warp::any().map(move || user_db.clone());

    let signup_route =
        warp::post2().and(path!("signup")).and(json_body).and(db.clone()).and_then(signup);


    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "DELETE", "OPTIONS"])
        .allow_headers(vec!["content-type"]);

    let routes = warp::post2().and(signup_route).with(cors);



    warp::serve(routes).run(([127, 0, 0, 1], 3030))
}


fn signup(signup: Signup, db: Db) -> Result<impl warp::Reply, warp::Rejection> {
    dbg!(signup);
    Ok(StatusCode::CREATED)
}
