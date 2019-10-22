use crate::db;
use crate::CONFIG;
use ldap3::{DerefAliases, LdapConn, Scope, SearchEntry, SearchOptions};
//use openssl::rsa::{Padding, Rsa};
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
                /*//let mut password_bytes = vec![0u8; 16];
                //password_bytes = crate::crypto::get_random(password_bytes);
                //let password = std::str::from_utf8(password_bytes.as_slice()).unwrap();
                let password = "T4mWB£rp3pU[µ:93";
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
                // Generate RSA keypair with openssl
                let encrypted_private_key = Some(String::from("2.OePZ1iws1FGn+POKtdgusQ==|YrYwp1+GE3J4zad9eI2HrE55CE0UqsMrbL2NR1GDP1s/P/WBFK4RQA5eUWcykXopj0QjY6/Ei6LX0cwpDophBLBQben9W7dVY1LoujGIF6DVTK7kSWu1bgLyn5UT6PdYtrfD2bByCeF5Ygh6KdcfqbYq7R2MxDjpZAtUe4NzxqOQH9wwmFT3R4PXUeNebKDLa9Uzn69kaXUkLhIqDZzVkJ1yAhbRdrXo3YNNrapplvDYSioa3l1KroUXiO2FBilAcpgIMlfJSVQd7tY7S9aY1eCBvhCtRiIozRTYzP6v6AvM8EgKneJ6mF6dPoI71g8xsA0/nSh13SMeB98gEzyOjbngCEzpqaalWgrCI5Qig3M/sfi7pvmIXaI9KoZxZ4wvqq4uism8pSHLMTAvWpP4TZTiOUC+Kt9GAifl9n/4rDdW+fUE+oP3ohJBexSuP3SeH6qIgcK+OHIKkT0mAkTTUq2jlLPXI5MYPiqMsE5qVLMkXkowbDQtolIoi16zHOFK7GZZnOTZANM2n1EKTrPQQubPV51zV5DZiTA6i89SYzDne6+VFk9eu7UbaP/pvXQBEDgmHUjJIBsNDTVN5Wd93GzQ9FnaqCATj64OHoinObVpzl4/tNc60hMLc/3hTx5R5CU4Q4/Ea9tN7QNjNeB6gCWJcjEnwm0/6FojPKO7QTbPCbIzbRzGEY/R2f8ByZ3IIcDb2NA+cm1DMTfdwztyyPjJsqUmUyuFWEJBUI6++cxVkpt9TS2JUEb3liNVN4jkUOJxAEGz4EbCihqjQwb9ojJs58Gj1u1IyjsE/WhcKNCIxSbX+/vr6mS9fxokR9JcGb2ACuCVeGWL/wlQsQFf6z9nHjiG9LmsmnJzk8gVqSC++wTw2DXRnarLRpzPqDJAMSSJHjDqjv2teR0WcvhbEj7v0m2EW7n73WjKccnPQKl5C4Vkjah80uFywjNCt8zJQq6BbrH2SyFOmun7rZThtRRu035TZzV20m8ZSqp0kfPIAcCFJckOQ5Pvk/6av4k8zgw537z41p0SU656Xe0Fsy3X6ibHDf1ZZYPmHboJlP5PCTaLGPJF6w6cD6tK/UktNQI2N5uMcBKvUYvDd8NNdjhuRPaOTszoLT68Bj7aTF8KTRvSQimJWglt+fRqEMGWnw+OfyO12/3Sv5o3iyz3H5JQUZFJwO8Zm1i7mLmKPp70YrPRWPDTUNWWPGQ6B1Qh7AQrL/0ywMQAxL++SB2jrv6Lc6pDgs3wy0drNiPQVnK8UfL1RSQE4xm4tnFaPGmYy7WF4lrSSCFrHz7Jq7Tw+4zZCOT+jFOvRAlSB0H68Gj3vTYN5cPMeFJPy6/04JNwp+D2Gi3Egu/AhzVAZO4OxiI/jLXB4NqhO4AB7iaj4nIDjNzjLpu59Uttwf5K71+fVUV8iBMKl3PVrB+o6GY/eiV4TfBzU0W351uGQ0xbXjsE93NXtIzBUUvU6rMaBIEJZDX2PmutG42FJkHIjqPvgFmeVCK7kr7upyA33eryQzWvwWMQNB3nmsJ4O19SxXfRDEbSdAl7lVpnucPh5gYvRx0Brmz0ZzaSw7UbMppy47irGjGoOzaCj394vWxKtIkR4AHxfvn6X93IFUanQsnsiswU13TLVzLD28QEg/WPxUg=|uag+TmENC8PNdiWsiSWobwpN7tXnC+NMMuRAxMkP3Po="));
                let public_key = Some(String::from("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwxJI7FZhQCGHdRwiqvAzpU4gYWNJ5JNVWeO9DPT5jy4ejx38ogRlsqSfdxaDwTufNcil7XBSDZgdUkPh1IizKQhn55Y2e4XxF5RQ8Aoi/Yp4efpYxG6m5DoAfFS7OWdXdwtlbluUTc3VeRYV80uHzjOUp89XPyfFjVRMkQB57SBiRubvCzZJ5C667PyVmwhkn/wTJuYT7F3OWQMPUokj67wGFzNBtEOSoN1MrM5B/tmyZGUMLfosGT3BUuBj4Z/Igyk4NCStgAyqJDIKzcNpIhgUJ7W9oMFw1lMfST9qyZ/fV7nG/iaH+J2dUr0mZ8nOs4jL+CUkbWiL83ekwYeTiwIDAQAB"));
                user.private_key = encrypted_private_key;
                user.public_key = public_key;*/
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
