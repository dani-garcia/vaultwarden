#![feature(plugin)]

#![plugin(rocket_codegen)]
extern crate rocket;
extern crate rocket_contrib;
extern crate reqwest;

use std::io::{self, Cursor};
use std::str::FromStr;
use std::path::{Path, PathBuf};

use rocket::{Request, Response};
use rocket::config::Config;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http;
use rocket::response::NamedFile;

use reqwest::header::{self, Headers};

/**
** These routes are here to avoid showing errors in the console,
** redirect the body data to the fairing and show the web vault.
**/
#[get("/")]
fn index() -> io::Result<NamedFile> {
    NamedFile::open(Path::new("web-vault").join("index.html"))
}

#[get("/<p..>")] // Only match this if the other routes don't match
fn get(p: PathBuf) -> io::Result<NamedFile> {
    NamedFile::open(Path::new("web-vault").join(p))
}

#[delete("/<_p..>")]
fn delete(_p: PathBuf) {}

#[put("/<_p..>", data = "<d>")]
fn put(_p: PathBuf, d: Vec<u8>) -> Vec<u8> { d }

#[post("/<_p..>", data = "<d>")]
fn post(_p: PathBuf, d: Vec<u8>) -> Vec<u8> { d }


fn main() {
    let config = Config::development().unwrap();

    rocket::custom(config, false)
        .mount("/", routes![get, put, post, delete, index])
        .attach(ProxyFairing { client: reqwest::Client::new() })
        .launch();
}

struct ProxyFairing {
    client: reqwest::Client
}

impl Fairing for ProxyFairing {
    fn info(&self) -> Info {
        Info {
            name: "Proxy Fairing",
            kind: Kind::Launch | Kind::Response,
        }
    }

    fn on_launch(&self, _rocket: &rocket::Rocket) {
        println!("Started proxy on locahost:8000");
    }

    fn on_response(&self, req: &Request, res: &mut Response) {
        // Prepare the data to make the request
        // -------------------------------------

        let url = {
            let url = req.uri().as_str();

            // Check if we are outside the API paths
            if !url.starts_with("/api/")
                && !url.starts_with("/identity/") {
                return;
            }

            // Replace the path with the real server URL
            url.replacen("/api/", "https://api.bitwarden.com/", 1)
                .replacen("/identity/", "https://identity.bitwarden.com/", 1)
        };

        let host = url.split("/").collect::<Vec<_>>()[2];
        let headers = headers_rocket_to_reqwest(req.headers(), host);
        let method = reqwest::Method::from_str(req.method().as_str()).unwrap();
        let body = res.body_bytes();

        println!("\n\nREQ. {} {}", req.method().as_str(), url);
        println!("HEADERS. {:#?}", headers);
        if let Some(ref body) = body {
            let body_string = String::from_utf8_lossy(body);
            if !body_string.contains("<!DOCTYPE html>") {
                println!("BODY. {:?}", body_string);
            }
        }


        // Execute the request
        // -------------------------------------
        let mut client = self.client.request(method, &url);
        let request_builder = client.headers(headers);

        if let Some(body_vec) = body {
            request_builder.body(body_vec);
        }

        let mut server_res = match request_builder.send() {
            Ok(response) => response,
            Err(e) => {
                res.set_status(http::Status::BadRequest);
                res.set_sized_body(Cursor::new(e.to_string()));
                return;
            }
        };

        // Get the response values
        // -------------------------------------
        let mut res_body: Vec<u8> = vec![];
        server_res.copy_to(&mut res_body).unwrap();

        let res_status = server_res.status().as_u16();
        let mut res_headers = server_res.headers().clone();

        // These headers break stuff
        res_headers.remove::<header::TransferEncoding>();
        res_headers.remove::<header::ContentLength>();

        println!("\n\nRES. {} {}", res_status, url);
        // Nothing interesting here
        // println!("HEADERS. {:#?}", res_headers);
        println!("BODY. {:?}", String::from_utf8_lossy(&res_body));

        // Prepare the response
        // -------------------------------------
        res.set_status(http::Status::from_code(res_status).unwrap_or(http::Status::BadRequest));

        headers_reqwest_to_rocket(&res_headers, res);
        res.set_sized_body(Cursor::new(res_body));
    }
}

fn headers_rocket_to_reqwest(headers: &http::HeaderMap, host: &str) -> Headers {
    let mut new_headers = Headers::new();

    for header in headers.iter() {
        let name = header.name().to_string();

        let value = if name.to_lowercase() != "host" {
            header.value().to_string()
        } else {
            host.to_string()
        };

        new_headers.set_raw(name, value);
    }
    new_headers
}

fn headers_reqwest_to_rocket(headers: &Headers, res: &mut Response) {
    for header in headers.iter() {
        res.set_raw_header(header.name().to_string(), header.value_string());
    }
}
