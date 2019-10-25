use crate::db::{init_pool, models::*, DbConn};
use crate::mail;
use crate::CONFIG;
use ldap3::{DerefAliases, LdapConn, Scope, SearchEntry, SearchOptions};
//use openssl::rsa::{Padding, Rsa};

use std::collections::HashSet;

use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

pub fn launch_ldap_connector() {
    std::thread::spawn(move || {
        let pool = init_pool();
        let conn = DbConn(pool.get().expect("Couldn't connect to DB."));
        let interval = Duration::from_secs(CONFIG.ldap_sync_interval());
        loop {
            if CONFIG._enable_ldap() {
                match sync_from_ldap(&conn) {
                    Ok(_) => println!("Sucessfully synced LDAP users"),
                    Err(error) => println!("Couldn't sync from LDAP, check LDAP config : {:?}", error),
                }
            }
            sleep(interval);
        }
    });
}

/// Invite all LDAP users to Bitwarden
fn sync_from_ldap(conn: &DbConn) -> Result<(), Box<Error>> {
    let existing_users = get_existing_users(&conn).expect("Error: Failed to get existing users from Bitwarden");
    let mut num_users = 0;
    let mut ldap_emails = HashSet::new();
    for ldap_user in search_entries()? {
        // Safely get first email from list of emails in field
        if let Some(user_email) = ldap_user.attrs.get("mail").and_then(|l| (l.first())) {
            ldap_emails.insert(user_email.to_string());
            if !existing_users.contains(user_email) {
                println!("Try to add user: {}", user_email);
                // Invite user
                if !CONFIG.invitations_allowed() {
                    println!("Invitations are not allowed");
                }

                let mut user = User::new(user_email.to_string());
                user.save(conn)?;

                if CONFIG.mail_enabled() {
                    let org_name = "bitwarden_rs";
                    mail::send_invite(&user.email, &user.uuid, None, None, &org_name, None)?;
                } else {
                    let invitation = Invitation::new(user_email.to_string());
                    invitation.save(conn)?;
                }
                num_users = num_users + 1;
            }
        } else {
            println!("Warning: Email field, mail, not found on user");
        }
    }

    for bw_email in existing_users {
        if !ldap_emails.contains(&bw_email) {
            // Delete user
            User::find_by_mail(bw_email.as_ref(), conn).unwrap().delete(conn)?;
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
fn get_existing_users(conn: &DbConn) -> Result<HashSet<String>, Box<Error>> {
    let all_users = User::get_all(conn);

    let mut user_emails = HashSet::with_capacity(all_users.len());
    for user in all_users {
        user_emails.insert(user.email);
    }

    Ok(user_emails)
}
