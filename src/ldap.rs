extern crate ldap3;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_timer;

use std::error::Error;
use std::thread;
use std::time::{Duration, Instant};

use ldap3::{DerefAliases, LdapConnAsync, Scope, SearchEntry, SearchOptions};
use tokio::prelude::*;
use tokio::timer::Interval;
use tokio_core::reactor::{Core, Handle};

use crate::db;
use crate::db::models::{Invitation, User};
use crate::db::DbConn;
use crate::CONFIG;

/// Generates invites for all users in LDAP who don't yet have an account or invite.
fn invite_from_results(conn: DbConn, results: Vec<SearchEntry>) -> Result<(), Box<Error>> {
    let mail_field = CONFIG.ldap_mail_field();
    for ldap_user in results {
        if let Some(user_email) = ldap_user.attrs[mail_field.as_str()].first() {
            match User::find_by_mail(user_email.as_str(), &conn) {
                Some(_) => println!("User already exists with email: {}", user_email),
                None => {
                    println!("New user, should try to add invite: {}", user_email);
                    match Invitation::find_by_mail(user_email.as_str(), &conn) {
                        Some(_) => println!("User invite exists for {}", user_email),
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

/// Initializes an LdapConnAsync client using provided configuration
fn new_ldap_client_async(handle: &Handle) -> Result<LdapConnAsync, Box<Error>> {
    let scheme = if CONFIG.ldap_ssl() { "ldaps" } else { "ldap" };
    let host = CONFIG.ldap_host().unwrap();
    let port = CONFIG.ldap_port().to_string();

    let ldap_uri = &format!("{}://{}:{}", scheme, host, port);

    let ldap = LdapConnAsync::new(ldap_uri, &handle)?;

    Ok(ldap)
}

/// Given syncs users from LDAP
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
            // Can't figure out how to use this result
            invite_from_results(conn, entries).expect("Could not invite users");
            Ok(())
        })
        .map_err(|e| panic!("Error searching: {:?}", e));

    handle.spawn(sync);

    Ok(())
}

/// Starts a new thread with event loop to sync LDAP users
pub fn start_ldap_sync() -> Result<(), Box<Error>> {
    thread::spawn(move || {
        let mut core = Core::new().expect("Could not create core");
        let handle = core.handle();

        let now = Instant::now();
        let sync_interval = CONFIG.ldap_sync_interval().clone();

        let task = Interval::new(now, Duration::from_secs(sync_interval))
            .for_each(|_| {
                // Can't figure out how to get this error handled
                ldap_sync(&handle).expect("Failed to sync from LDAP");
                Ok(())
            })
            .map_err(|e| panic!("LDAP sync interval errored: {:?}", e));

        core.run(task)
    });

    Ok(())
}
