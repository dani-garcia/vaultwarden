extern crate ldap3;

use std::error::Error;

use ldap3::{DerefAliases, LdapConn, Scope, SearchEntry, SearchOptions};

use crate::db::models::User;
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
