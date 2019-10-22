use crate::db;
use crate::CONFIG;
use ldap3::{DerefAliases, LdapConn, Scope, SearchEntry, SearchOptions};
use ring::{digest, pbkdf2};
use std::collections::HashSet;
use std::convert::TryInto;
use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

pub fn launch_ldap_connector() {
    std::thread::spawn(move || {
        let pool = db::init_pool();
        let conn = db::DbConn(pool.get().expect("Couldn't connect to DB."));
        let interval = Duration::from_secs(CONFIG.ldap_sync_interval());
        loop {
            if CONFIG._enable_ldap() {
                sync_from_ldap(&conn).expect("Couldn't sync users from LDAP.");
            }
            sleep(interval);
        }
    });
}

/// Invite all LDAP users to Bitwarden
fn sync_from_ldap(conn: &db::DbConn) -> Result<(), Box<Error>> {
    let existing_users = get_existing_users(&conn).expect("Error: Failed to get existing users from Bitwarden");
    let mut num_users = 0;
    for ldap_user in search_entries()? {
        // Safely get first email from list of emails in field
        if let Some(user_email) = ldap_user.attrs.get("mail").and_then(|l| (l.first())) {
            if !existing_users.contains(user_email) {
                println!("Try to add user: {}", user_email);
                // Add user
                let mut user = db::models::User::new(user_email.to_string());
                let mut password_bytes = vec![0u8; 16];
                password_bytes = crate::crypto::get_random(password_bytes);
                let password = std::str::from_utf8(password_bytes.as_slice()).unwrap();
                user.set_password(password);
                user.client_kdf_iter = 100000;
                let key = &mut [0u8; digest::SHA256_OUTPUT_LEN];
                pbkdf2::derive(
                    &digest::SHA256,
                    std::num::NonZeroU32::new(user.client_kdf_iter.try_into().unwrap()).unwrap(),
                    user.email.as_bytes(),
                    password.as_bytes(),
                    key,
                );
                user.akey = String::from_utf8(key.to_vec()).unwrap();
                user.save(conn)?;
                num_users = num_users + 1;
            }
        } else {
            println!("Warning: Email field, mail, not found on user");
        }
    }

    // Maybe think about returning this value for some other use
    println!("Added {} user(s).", num_users);

    Ok(())
}

/// Retrieves search results from ldap
fn search_entries() -> Result<Vec<SearchEntry>, Box<Error>> {
    let ldap = LdapConn::new(CONFIG.ldap_host().as_str())?;
    ldap.simple_bind(CONFIG.ldap_bind_dn().as_str(), CONFIG.ldap_bind_password().as_str())?;

    let fields = vec!["uid", "givenname", "sn", "cn", "mail"];

    // TODO: Something something error handling
    let (results, _res) = ldap
        .with_search_options(SearchOptions::new().deref(DerefAliases::Always))
        .search(
            CONFIG.ldap_search_base_dn().as_str(),
            Scope::Subtree,
            CONFIG.ldap_search_filter().as_str(),
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

/// Creates set of email addresses for users that already exist in Bitwarden
fn get_existing_users(conn: &db::DbConn) -> Result<HashSet<String>, Box<Error>> {
    let all_users = db::models::User::get_all(conn);

    let mut user_emails = HashSet::with_capacity(all_users.len());
    for user in all_users {
        user_emails.insert(user.email);
    }

    Ok(user_emails)
}
