#[macro_use]
extern crate serde_derive;
mod utils;
use blake2::{Blake2b, VarBlake2b};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use scrypt::ScryptParams;
use wasm_bindgen::prelude::*;

// wee_alloc makes the memory allocater smaller -- better for WASM compiation
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// The scalar is the private key
type KeyPair = (Scalar, RistrettoPoint);

#[derive(Deserialize, Serialize, Debug)]
pub struct Response {
    pub public_key: RistrettoPoint,
    #[serde(with = "hex_serde")]
    pub challenge_response: [u8; 32],
    pub user_id: String,
}

/// The server and client do this to determine the base generator
fn base_point_from_domain(domain: &str) -> RistrettoPoint {
    use blake2::Digest;
    let mut hasher = Blake2b::new();
    hasher.input(domain.as_bytes());
    /// generates a point (uniformly) from a 64 byte hash output
    RistrettoPoint::from_hash(hasher)
}

/// Ran on the client -- convert their password to key pair
fn password_to_keypair(domain: &str, user_id: &str, password: &str) -> KeyPair {
    let base_point = base_point_from_domain(domain);

    // testing takes forever without this
    #[cfg(not(test))]
    let scrypt_params = ScryptParams::new(15, 8, 1).expect("these are valid");

    #[cfg(test)]
    let scrypt_params = ScryptParams::new(1, 8, 1).expect("these are valid");

    let mut output = [0u8; 64];
    let salt = format!("{}/{}", domain, user_id);
    scrypt::scrypt(
        password.as_bytes(),
        salt.as_bytes(),
        &scrypt_params,
        &mut output,
    )
    .expect("The output is a valid length");
    let pw_scalar = Scalar::from_bytes_mod_order_wide(&output);
    let pw_point = pw_scalar * base_point;
    (pw_scalar, pw_point)
}

#[wasm_bindgen]
pub fn password_to_public_key(domain: &str, user_id: &str, password: &str) -> JsValue {
    let keypair = password_to_keypair(domain, user_id, password);
    JsValue::from_serde(&keypair.1).unwrap()
}

// This method should be used from Rust (for tests)
fn _respond_to_challenge(
    domain: &str,
    user_id: &str,
    purpose: &str,
    password: &str,
    challenge: &[u8],
) -> Option<Response> {
    // Ristretto points are stored using four(?) field elements, but then can be compressed to 32 bytes.
    let challenge = CompressedRistretto::from_slice(challenge).decompress()?;

    let keypair = password_to_keypair(domain, user_id, password);
    // Calculate the Diffie-Hellman as the response
    let dh = keypair.0 * challenge;
    // Hash it with the "purpose" which adds some domain separation
    let challenge_response = hash_challenge_response(&dh, purpose);

    Some(Response {
        public_key: keypair.1,
        challenge_response,
        user_id: user_id.to_owned(),
    })
}

// This one is used from javascript
#[wasm_bindgen]
pub fn respond_to_challenge(
    domain: &str,
    user_id: &str,
    purpose: &str,
    password: &str,
    challenge: &[u8],
) -> JsValue {
    match _respond_to_challenge(domain, user_id, purpose, password, challenge) {
        Some(response) => JsValue::from_serde(&response).unwrap(),
        None => JsValue::NULL,
    }
}

// Both server and client do this
fn hash_challenge_response(dh: &RistrettoPoint, purpose: &str) -> [u8; 32] {
    use blake2::digest::{Input, VariableOutput};
    let mut result = [0u8; 32];
    let mut hasher = VarBlake2b::new(32).expect("this is a valid length");
    // Prefix the Diffie-Hellman challenge response with "purpose/"
    hasher.input(purpose.as_bytes());
    hasher.input(b"/");
    hasher.input(dh.compress().as_bytes());
    result.copy_from_slice(&hasher.vec_result()[..]);
    result
}

// SERVER SIDE ONLY STUFF
use rand::thread_rng; // Source of randomness appropriate for cryptography
use rand::RngCore;
use std::collections::HashMap;

#[derive(Clone, PartialEq, Debug)]
// The hash of the public key stored in the database
pub struct KeyId([u8; 32]);

pub struct UserDB {
    // username to key hash
    table: HashMap<String, KeyId>,
    pepper: [u8; 8],
}

impl Default for UserDB {
    fn default() -> Self {
        let mut pepper = [0u8; 8];
        thread_rng().fill_bytes(&mut pepper);
        UserDB {
            table: HashMap::default(),
            pepper,
        }
    }
}

impl UserDB {
    pub fn add_user(&mut self, user_id: String, key: &RistrettoPoint) {
        self.table.insert(user_id, self.keyid_from_public_key(&key));
    }

    pub fn get_key_id(&self, user_id: &str) -> Option<KeyId> {
        self.table.get(user_id).map(Clone::clone)
    }

    // calculate key hash from their public key and pepper
    pub fn keyid_from_public_key(&self, key: &RistrettoPoint) -> KeyId {
        #[cfg(not(test))]
        let scrypt_params = ScryptParams::new(15, 8, 1).expect("these are valid");
        #[cfg(test)]
        let scrypt_params = ScryptParams::new(1, 8, 1).expect("these are valid");
        let mut key_id = [0u8; 32];
        scrypt::scrypt(
            key.compress().as_bytes(),
            &self.pepper,
            &scrypt_params,
            &mut key_id,
        )
        .expect("The output is a valid length");
        KeyId(key_id)
    }
}

pub fn verify_response(
    challenge_keypair: &KeyPair,
    purpose: &str,
    response: &Response,
    user_db: &UserDB,
) -> bool {
    let is_correct_keyid = match user_db.get_key_id(&response.user_id) {
        Some(expected_key_id) => {
            let claimed_key_id = user_db.keyid_from_public_key(&response.public_key);
            expected_key_id == claimed_key_id
        }
        None => false,
    };

    let correct_response = {
        let dh = challenge_keypair.0 * response.public_key;
        hash_challenge_response(&dh, purpose)
    };

    return &correct_response[..] == &response.challenge_response[..] && is_correct_keyid;
}

pub fn generate_challenge(domain_point: &RistrettoPoint) -> KeyPair {
    let scalar = Scalar::random(&mut thread_rng());
    let point = scalar * domain_point;
    (scalar, point)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let mut user_db = UserDB::default();

        let domain_point = base_point_from_domain("foo.com");

        {
            let user = "alice";
            let (_, public_key) = password_to_keypair("foo.com", user, "p4ssword");
            user_db.add_user(user.to_owned(), &public_key);
        }

        {
            let user = "bob";
            let (_, public_key) = password_to_keypair("foo.com", user, "p4ssword");
            user_db.add_user(user.to_owned(), &public_key);
        }

        {
            assert_ne!(
                user_db.get_key_id("alice"),
                user_db.get_key_id("bob"),
                "Two users with the same password have different key ids"
            );
        }

        let challenge_keypair = generate_challenge(&domain_point);
        let challenge = challenge_keypair.1.compress();
        // // send challenge keypair to client

        {
            let alice_correct_response = _respond_to_challenge(
                "foo.com",
                "alice",
                "login",
                "p4ssword",
                challenge.as_bytes(),
            )
            .unwrap();
            assert!(verify_response(
                &challenge_keypair,
                "login",
                &alice_correct_response,
                &user_db
            ));

            let bob_correct_response =
                _respond_to_challenge("foo.com", "bob", "login", "p4ssword", challenge.as_bytes())
                    .unwrap();
            assert!(verify_response(
                &challenge_keypair,
                "login",
                &bob_correct_response,
                &user_db
            ));

            assert_ne!(
                alice_correct_response.challenge_response,
                bob_correct_response.challenge_response
            );
        }

        {
            let incorrect_password = _respond_to_challenge(
                "foo.com",
                "alice",
                "login",
                "passw0rd",
                challenge.as_bytes(),
            )
            .unwrap();
            assert!(
                !verify_response(&challenge_keypair, "login", &incorrect_password, &user_db),
                "wrong password"
            );
        }

        {
            let incorrect_domain = _respond_to_challenge(
                "bar.com",
                "alice",
                "login",
                "p4ssword",
                challenge.as_bytes(),
            )
            .unwrap();
            assert!(
                !verify_response(&challenge_keypair, "login", &incorrect_domain, &user_db),
                "wrong domain"
            );
        }

        {
            let incorrect_purpose = _respond_to_challenge(
                "bar.com",
                "alice",
                "login",
                "p4ssword",
                challenge.as_bytes(),
            )
            .unwrap();
            assert!(
                !verify_response(
                    &challenge_keypair,
                    "authorize-payment",
                    &incorrect_purpose,
                    &user_db
                ),
                "wrong purpose"
            )
        }
    }
}
