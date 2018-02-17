table! {
    attachments (id) {
        id -> Text,
        cipher_uuid -> Text,
        file_name -> Text,
        file_size -> Integer,
    }
}

table! {
    ciphers (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        folder_uuid -> Nullable<Text>,
        organization_uuid -> Nullable<Text>,
        #[sql_name = "type"]
        type_ -> Integer,
        data -> Text,
        favorite -> Bool,
    }
}

table! {
    collections (uuid) {
        uuid -> Text,
        org_uuid -> Text,
        name -> Text,
    }
}

table! {
    devices (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        name -> Text,
        #[sql_name = "type"]
        type_ -> Integer,
        push_token -> Nullable<Text>,
        refresh_token -> Text,
    }
}

table! {
    folders (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        name -> Text,
    }
}

table! {
    organizations (uuid) {
        uuid -> Text,
        name -> Text,
        billing_email -> Text,
    }
}

table! {
    users (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        email -> Text,
        name -> Text,
        password_hash -> Binary,
        salt -> Binary,
        password_iterations -> Integer,
        password_hint -> Nullable<Text>,
        key -> Text,
        private_key -> Nullable<Text>,
        public_key -> Nullable<Text>,
        totp_secret -> Nullable<Text>,
        totp_recover -> Nullable<Text>,
        security_stamp -> Text,
        equivalent_domains -> Text,
        excluded_globals -> Text,
    }
}

table! {
    users_collections (user_uuid, collection_uuid) {
        user_uuid -> Text,
        collection_uuid -> Text,
    }
}

table! {
    users_organizations (user_uuid, org_uuid) {
        user_uuid -> Text,
        org_uuid -> Text,
        key -> Text,
        status -> Integer,
        #[sql_name = "type"]
        type_ -> Integer,
    }
}

joinable!(attachments -> ciphers (cipher_uuid));
joinable!(ciphers -> folders (folder_uuid));
joinable!(ciphers -> users (user_uuid));
joinable!(collections -> organizations (org_uuid));
joinable!(devices -> users (user_uuid));
joinable!(folders -> users (user_uuid));
joinable!(users_collections -> collections (collection_uuid));
joinable!(users_collections -> users (user_uuid));
joinable!(users_organizations -> organizations (org_uuid));
joinable!(users_organizations -> users (user_uuid));

allow_tables_to_appear_in_same_query!(
    attachments,
    ciphers,
    collections,
    devices,
    folders,
    organizations,
    users,
    users_collections,
    users_organizations,
);
