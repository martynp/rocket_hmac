// src/main.rs
#[macro_use]
extern crate rocket;

use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose, Engine as _};

use openssl::hash::MessageDigest;
use openssl::x509::X509;

use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::{json::Json, Deserialize};
use rocket::State;

use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct Req<'r> {
    value: &'r str,
}

#[post("/some/path/<value>", data = "<req>")]
fn index(value: i32, auth: HmacAuth, req: Json<Req<'_>>) -> String {
    format!(
        "Called by: {}\nValue: {}\nJSON Value: {}",
        auth.0, value, req.value
    )
}

struct RootCAState {
    cert: Arc<Mutex<X509>>,
}

#[launch]
fn rocket() -> _ {
    let cert_str = std::include_str!("../keys/rootCA.crt");
    let cert = X509::from_pem(cert_str.as_bytes()).unwrap();

    let root_ca_state = RootCAState {
        cert: Arc::new(Mutex::new(cert)),
    };

    rocket::build()
        .attach(ChecksumFairing {})
        .manage(root_ca_state)
        .mount("/", routes![index])
}

struct HmacAuth(String);

#[derive(Debug)]
enum HmacAuthError {
    AuthorizationHeader(String),
    PublicKey(String),
    Invalid,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for HmacAuth {
    type Error = HmacAuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // <Method>\n
        // <Content-MD5>\n
        // <Content-SHA256>\n
        // <Path>

        let method = req.method().to_string().to_uppercase();
        let content_md5 = match req.meta.get::<String>(&"md5".into()) {
            Some(v) => v,
            None => return Outcome::Failure((Status::InternalServerError, HmacAuthError::Invalid)),
        };
        let content_sha256 = match req.meta.get::<String>(&"sha256".into()) {
            Some(v) => v,
            None => return Outcome::Failure((Status::InternalServerError, HmacAuthError::Invalid)),
        };

        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            method,
            content_md5,
            content_sha256,
            req.uri().path().as_str()
        );

        // Check we have a public key
        let public_key = match req.headers().get_one("x-public-key") {
            Some(key) => X509::from_pem(&general_purpose::STANDARD.decode(key).unwrap()).unwrap(),
            None => {
                return Outcome::Failure((
                    Status::BadRequest,
                    HmacAuthError::PublicKey("Missing".into()),
                ));
            }
        };

        // Check we have an auth header
        let auth = match validate_authorization_header(req.headers().get_one("authorization")) {
            Ok(a) => a,
            Err(e) => return Outcome::Failure((Status::BadRequest, e)),
        };

        // Get the root ca certificate and verify the public key was signed correctly
        let root_ca = match req.guard::<&State<RootCAState>>().await {
            rocket::outcome::Outcome::Success(root_ca) => &root_ca.cert,
            rocket::outcome::Outcome::Failure(_) | rocket::outcome::Outcome::Forward(_) => {
                return Outcome::Failure((Status::InternalServerError, HmacAuthError::Invalid));
            }
        };

        let root_public_key = root_ca.lock().unwrap();
        match public_key.verify(&root_public_key.public_key().unwrap().as_ref()) {
            Ok(v) => {
                if v == false {
                    return Outcome::Failure((
                        Status::BadRequest,
                        HmacAuthError::PublicKey("Public key does not verify".into()),
                    ));
                }
            }
            Err(e) => {
                return Outcome::Failure((
                    Status::BadRequest,
                    HmacAuthError::PublicKey(format!("Error verifying: {}", e)),
                ));
            }
        }

        let pkey = &public_key.public_key();
        let pkey = match pkey {
            Ok(p) => p,
            Err(e) => {
                return Outcome::Failure((
                    Status::BadRequest,
                    HmacAuthError::PublicKey(format!("Error getting key from certificate: {}", e)),
                ));
            }
        };
        let mut verifier =
            openssl::sign::Verifier::new(MessageDigest::sha256(), pkey.as_ref()).unwrap();
        verifier.update(&string_to_sign.as_bytes()).unwrap();
        if verifier.verify(&auth).unwrap() == false {
            return Outcome::Failure((Status::BadRequest, HmacAuthError::Invalid));
        }

        let sig = public_key
            .serial_number()
            .to_bn()
            .unwrap()
            .to_hex_str()
            .unwrap()
            .to_ascii_lowercase();
        return Outcome::Success(HmacAuth(sig));

        fn validate_authorization_header(auth: Option<&str>) -> Result<Vec<u8>, HmacAuthError> {
            return match auth {
                Some(auth) => {
                    let auth = match auth.strip_prefix("HMAC ") {
                        Some(a) => a,
                        None => {
                            return Err(HmacAuthError::AuthorizationHeader(
                                "Incorrect format".into(),
                            ))
                        }
                    };
                    match general_purpose::STANDARD.decode(auth) {
                        Ok(auth) => Ok(auth),
                        Err(e) => {
                            return Err(HmacAuthError::AuthorizationHeader(format!(
                                "Unable to decode: {}",
                                e
                            )))
                        }
                    }
                }

                None => return Err(HmacAuthError::AuthorizationHeader("Missing".into())),
            };
        }
    }
}

struct ChecksumFairing {}

use rocket::data::{Data, ToByteUnit};
use rocket::fairing::{Fairing, Info, Kind};

#[rocket::async_trait]
impl Fairing for ChecksumFairing {
    fn info(&self) -> Info {
        Info {
            name: "Data Peeker",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, data: &mut Data<'_>) {
        // Guards for content-type (application/json) and content-length (less than 1 MiB)

        if req.content_type().is_none() {
            return;
        }

        if let Some(content_type) = req.content_type() {
            if *content_type != rocket::http::ContentType::JSON {
                return;
            }
        }

        if req.headers().contains("Content-Length") == false {
            return;
        }

        // Create an empty Data object and swap with borrowed data reference
        let mut swap_data = rocket::data::Data::local(vec![]);
        std::mem::swap(data, &mut swap_data);

        // Get the message content
        let request_content = swap_data
            .open(10.megabytes())
            .into_bytes()
            .await
            .unwrap()
            .value;

        let md5_digest = md5::compute(&request_content).0;
        req.meta
            .insert("md5".into(), general_purpose::STANDARD.encode(&md5_digest));

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(request_content.as_slice());
        let sha256_digest = sha256_hasher.finalize();
        req.meta.insert(
            "sha256".into(),
            general_purpose::STANDARD.encode(&sha256_digest),
        );

        // Put the data in to a new Data object and swap it back in with the borrowed data reference
        let mut new_data = rocket::data::Data::local(request_content);
        std::mem::swap(data, &mut new_data);
    }
}
