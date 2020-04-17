table! {
    attachments (id) {
        id -> Varchar,
        cipher_uuid -> Varchar,
        file_name -> Text,
        file_size -> Integer,
        akey -> Nullable<Text>,
    }
}

table! {
    ciphers (uuid) {
        uuid -> Varchar,
        created_at -> Datetime,
        updated_at -> Datetime,
        user_uuid -> Nullable<Varchar>,
        organization_uuid -> Nullable<Varchar>,
        atype -> Integer,
        name -> Text,
        notes -> Nullable<Text>,
        fields -> Nullable<Text>,
        data -> Text,
        favorite -> Bool,
        password_history -> Nullable<Text>,
        deleted_at -> Nullable<Datetime>,
    }
}

table! {
    ciphers_collections (cipher_uuid, collection_uuid) {
        cipher_uuid -> Varchar,
        collection_uuid -> Varchar,
    }
}

table! {
    collections (uuid) {
        uuid -> Varchar,
        org_uuid -> Varchar,
        name -> Text,
    }
}

table! {
    devices (uuid) {
        uuid -> Varchar,
        created_at -> Datetime,
        updated_at -> Datetime,
        user_uuid -> Varchar,
        name -> Text,
        atype -> Integer,
        push_token -> Nullable<Text>,
        refresh_token -> Text,
        twofactor_remember -> Nullable<Text>,
    }
}

table! {
    folders (uuid) {
        uuid -> Varchar,
        created_at -> Datetime,
        updated_at -> Datetime,
        user_uuid -> Varchar,
        name -> Text,
    }
}

table! {
    folders_ciphers (cipher_uuid, folder_uuid) {
        cipher_uuid -> Varchar,
        folder_uuid -> Varchar,
    }
}

table! {
    invitations (email) {
        email -> Varchar,
    }
}

table! {
    org_policies (uuid) {
        uuid -> Varchar,
        org_uuid -> Varchar,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
    }
}

table! {
    organizations (uuid) {
        uuid -> Varchar,
        name -> Text,
        billing_email -> Text,
    }
}

table! {
    twofactor (uuid) {
        uuid -> Varchar,
        user_uuid -> Varchar,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
        last_used -> Integer,
    }
}

table! {
    users (uuid) {
        uuid -> Varchar,
        created_at -> Datetime,
        updated_at -> Datetime,
        verified_at -> Nullable<Datetime>,
        last_verifying_at -> Nullable<Datetime>,
        login_verify_count -> Integer,
        email -> Varchar,
        email_new -> Nullable<Varchar>,
        email_new_token -> Nullable<Varchar>,
        name -> Text,
        password_hash -> Blob,
        salt -> Blob,
        password_iterations -> Integer,
        password_hint -> Nullable<Text>,
        akey -> Text,
        private_key -> Nullable<Text>,
        public_key -> Nullable<Text>,
        totp_secret -> Nullable<Text>,
        totp_recover -> Nullable<Text>,
        security_stamp -> Text,
        equivalent_domains -> Text,
        excluded_globals -> Text,
        client_kdf_type -> Integer,
        client_kdf_iter -> Integer,
    }
}

table! {
    users_collections (user_uuid, collection_uuid) {
        user_uuid -> Varchar,
        collection_uuid -> Varchar,
        read_only -> Bool,
    }
}

table! {
    users_organizations (uuid) {
        uuid -> Varchar,
        user_uuid -> Varchar,
        org_uuid -> Varchar,
        access_all -> Bool,
        akey -> Text,
        status -> Integer,
        atype -> Integer,
    }
}

joinable!(attachments -> ciphers (cipher_uuid));
joinable!(ciphers -> organizations (organization_uuid));
joinable!(ciphers -> users (user_uuid));
joinable!(ciphers_collections -> ciphers (cipher_uuid));
joinable!(ciphers_collections -> collections (collection_uuid));
joinable!(collections -> organizations (org_uuid));
joinable!(devices -> users (user_uuid));
joinable!(folders -> users (user_uuid));
joinable!(folders_ciphers -> ciphers (cipher_uuid));
joinable!(folders_ciphers -> folders (folder_uuid));
joinable!(org_policies -> organizations (org_uuid));
joinable!(twofactor -> users (user_uuid));
joinable!(users_collections -> collections (collection_uuid));
joinable!(users_collections -> users (user_uuid));
joinable!(users_organizations -> organizations (org_uuid));
joinable!(users_organizations -> users (user_uuid));

allow_tables_to_appear_in_same_query!(
    attachments,
    ciphers,
    ciphers_collections,
    collections,
    devices,
    folders,
    folders_ciphers,
    invitations,
    org_policies,
    organizations,
    twofactor,
    users,
    users_collections,
    users_organizations,
);
