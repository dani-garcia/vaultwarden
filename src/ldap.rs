extern crate ldap3;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_timer;

use std::error::Error;
use std::thread;
use std::time::Duration;

use ldap3::{DerefAliases, LdapConn, LdapConnAsync, Scope, SearchEntry, SearchOptions};
use tokio::prelude::*;
use tokio::timer::Interval;
use tokio_core::reactor::{Core, Handle};

use crate::db;
use crate::db::models::{Invitation, User};
use crate::db::DbConn;
use crate::CONFIG;

fn main() {
    match do_search() {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    }
}

/// Creates an LDAP connection, authenticating if necessary
fn ldap_client() -> Result<LdapConn, Box<Error>> {
    let scheme = if CONFIG.ldap_ssl() { "ldaps" } else { "ldap" };
    let host = CONFIG.ldap_host().unwrap();
    let port = CONFIG.ldap_port().to_string();

    let ldap = LdapConn::new(&format!("{}://{}:{}", scheme, host, port))?;

    match (&CONFIG.ldap_bind_dn(), &CONFIG.ldap_bind_password()) {
        (Some(bind_dn), Some(pass)) => {
            match ldap.simple_bind(bind_dn, pass) {
                _ => {}
            };
        }
        (_, _) => {}
    };

    Ok(ldap)
}

/*
 * /// Creates an LDAP connection, authenticating if necessary
 * fn ldap_async_client(handle: &Handle, core: &Core) -> Result<LdapConnAsync, Box<Error>> {
 *     let scheme = if CONFIG.ldap_ssl() { "ldaps" } else { "ldap" };
 *     let host = CONFIG.ldap_host().unwrap();
 *     let port = CONFIG.ldap_port().to_string();
 *
 *     let ldap_uri = &format!("{}://{}:{}", scheme, host, port);
 *
 *     let ldap = LdapConnAsync::new(ldap_uri, &handle)?.and_then(|ldap| {
 *         match (&CONFIG.ldap_bind_dn(), &CONFIG.ldap_bind_password()) {
 *             (Some(bind_dn), Some(pass)) => {
 *                 match ldap.simple_bind(bind_dn, pass) {
 *                     _ => {}
 *                 };
 *             }
 *             (_, _) => {}
 *         };
 *     });
 *
 *     Ok(ldap)
 * }
 */

/// Retrieves search results from ldap
fn search_entries() -> Result<Vec<SearchEntry>, Box<Error>> {
    let ldap = ldap_client()?;

    let mail_field = CONFIG.ldap_mail_field();
    let fields = vec!["uid", "givenname", "sn", "cn", mail_field.as_str()];

    // TODO: Something something error handling
    let (results, _res) = ldap
        .with_search_options(SearchOptions::new().deref(DerefAliases::Always))
        .search(
            &CONFIG.ldap_search_base_dn().unwrap(),
            Scope::Subtree,
            &CONFIG.ldap_search_filter(),
            fields,
        )?
        .success()?;

    // Build list of entries
    let mut entries = Vec::new();
    for result in results {
        entries.push(SearchEntry::construct(result));
    }

    Ok(entries)
}

pub fn do_search() -> Result<(), Box<Error>> {
    let mail_field = CONFIG.ldap_mail_field();
    let entries = search_entries()?;
    for user in entries {
        println!("{:?}", user);
        if let Some(user_email) = user.attrs[mail_field.as_str()].first() {
            println!("{}", user_email);
        }
    }

    Ok(())
}

pub fn invite_from_ldap(conn: DbConn) -> Result<(), Box<Error>> {
    let mail_field = CONFIG.ldap_mail_field();
    for ldap_user in search_entries()? {
        if let Some(user_email) = ldap_user.attrs[mail_field.as_str()].first() {
            let user = match User::find_by_mail(user_email.as_str(), &conn) {
                Some(user) => println!("User already exists with email: {}", user_email),
                None => println!("New user, should add to invites: {}", user_email),
            };
        }
    }

    Ok(())
}

fn invite_from_results(conn: DbConn, results: Vec<SearchEntry>) -> Result<(), Box<Error>> {
    let mail_field = CONFIG.ldap_mail_field();
    for ldap_user in results {
        if let Some(user_email) = ldap_user.attrs[mail_field.as_str()].first() {
            match User::find_by_mail(user_email.as_str(), &conn) {
                Some(user) => println!("User already exists with email: {}", user_email),
                None => {
                    println!("New user, should try to add invite: {}", user_email);
                    match Invitation::find_by_mail(user_email.as_str(), &conn) {
                        Some(invite) => println!("User invite exists for {}", user_email),
                        None => {
                            println!("Creating new invite for {}", user_email);
                            Invitation::new(user_email.clone()).save(&conn)?;
                        }
                    }
                }
            };
        }
    }

    Ok(())
}

pub fn start_ldap_sync_old() -> Result<(), Box<Error>> {
    let duration = Duration::from_secs(2);
    let task = Interval::new_interval(duration)
        .take(10)
        .for_each(|instant| {
            let db_conn = db::get_dbconn().expect("Can't reach database");
            match invite_from_ldap(db_conn) {
                Ok(_) => println!("Worked!"),
                Err(e) => {
                    println!("{}", e);
                    panic!("Failed!");
                }
            };
            Ok(())
        })
        .map_err(|e| panic!("interval errored: {:?}", e));

    tokio::run(task);

    Ok(())
}

fn new_ldap_client_async(handle: &Handle) -> Result<LdapConnAsync, Box<Error>> {
    let scheme = if CONFIG.ldap_ssl() { "ldaps" } else { "ldap" };
    let host = CONFIG.ldap_host().unwrap();
    let port = CONFIG.ldap_port().to_string();

    let ldap_uri = &format!("{}://{}:{}", scheme, host, port);

    let ldap = LdapConnAsync::new(ldap_uri, &handle)?;

    Ok(ldap)
}

fn ldap_sync(handle: &Handle) -> Result<(), Box<Error>> {
    let handle = handle.clone();

    let ldap = new_ldap_client_async(&handle)?;
    let sync = ldap
        .and_then(|ldap| {
            // Maybe bind
            match (&CONFIG.ldap_bind_dn(), &CONFIG.ldap_bind_password()) {
                (Some(bind_dn), Some(pass)) => {
                    ldap.simple_bind(bind_dn, pass);
                }
                (_, _) => {}
            };

            let mail_field = CONFIG.ldap_mail_field();
            let fields = vec!["uid", "givenname", "sn", "cn", mail_field.as_str()];
            ldap.with_search_options(SearchOptions::new().deref(DerefAliases::Always))
                .search(
                    &CONFIG.ldap_search_base_dn().unwrap(),
                    Scope::Subtree,
                    &CONFIG.ldap_search_filter(),
                    fields,
                )
        })
        .and_then(|response| response.success())
        .and_then(|(results, _res)| {
            let mut entries = Vec::new();
            for result in results {
                entries.push(SearchEntry::construct(result));
            }
            let conn = db::get_dbconn().expect("Can't reach database");
            invite_from_results(conn, entries);
            Ok(())
        })
        .map_err(|e| panic!("Error searching: {:?}", e));

    handle.spawn(sync);

    Ok(())
}

pub fn start_ldap_sync() -> Result<(), Box<Error>> {
    thread::spawn(move || {
        let mut core = Core::new().expect("Could not create core");
        let handle = core.handle();

        let task = Interval::new_interval(Duration::from_secs(5))
            .take(10)
            .for_each(|instant| {
                ldap_sync(&handle);
                Ok(())
            })
            .map_err(|e| panic!("interval errored: {:?}", e));

        core.run(task);
    });

    Ok(())
}
