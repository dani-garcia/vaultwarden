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
        attachments -> Nullable<Binary>,
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
    }
}

joinable!(ciphers -> folders (folder_uuid));
joinable!(ciphers -> users (user_uuid));
joinable!(devices -> users (user_uuid));
joinable!(folders -> users (user_uuid));

allow_tables_to_appear_in_same_query!(
    ciphers,
    devices,
    folders,
    users,
);
