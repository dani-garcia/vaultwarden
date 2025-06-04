// @generated automatically by Diesel CLI.

diesel::table! {
    attachments (id) {
        id -> Text,
        cipher_uuid -> Text,
        file_name -> Text,
        file_size -> Integer,
        akey -> Nullable<Text>,
    }
}

diesel::table! {
    auth_requests (uuid) {
        uuid -> Text,
        user_uuid -> Text,
        organization_uuid -> Nullable<Text>,
        request_device_identifier -> Text,
        device_type -> Integer,
        request_ip -> Text,
        response_device_id -> Nullable<Text>,
        access_code -> Text,
        public_key -> Text,
        enc_key -> Nullable<Text>,
        master_password_hash -> Nullable<Text>,
        approved -> Nullable<Bool>,
        creation_date -> Timestamp,
        response_date -> Nullable<Timestamp>,
        authentication_date -> Nullable<Timestamp>,
    }
}

diesel::table! {
    ciphers (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Nullable<Text>,
        organization_uuid -> Nullable<Text>,
        atype -> Integer,
        name -> Text,
        notes -> Nullable<Text>,
        fields -> Nullable<Text>,
        data -> Text,
        password_history -> Nullable<Text>,
        deleted_at -> Nullable<Timestamp>,
        reprompt -> Nullable<Integer>,
        key -> Nullable<Text>,
    }
}

diesel::table! {
    ciphers_collections (cipher_uuid, collection_uuid) {
        cipher_uuid -> Text,
        collection_uuid -> Text,
    }
}

diesel::table! {
    collections (uuid) {
        uuid -> Text,
        org_uuid -> Text,
        name -> Text,
        external_id -> Nullable<Text>,
    }
}

diesel::table! {
    collections_groups (rowid) {
        rowid -> Integer,
        collections_uuid -> Text,
        groups_uuid -> Text,
        read_only -> Bool,
        hide_passwords -> Bool,
        manage -> Bool,
    }
}

diesel::table! {
    devices (uuid, user_uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        name -> Text,
        atype -> Integer,
        push_token -> Nullable<Text>,
        refresh_token -> Text,
        twofactor_remember -> Nullable<Text>,
        push_uuid -> Nullable<Text>,
    }
}

diesel::table! {
    emergency_access (uuid) {
        uuid -> Text,
        grantor_uuid -> Nullable<Text>,
        grantee_uuid -> Nullable<Text>,
        email -> Nullable<Text>,
        key_encrypted -> Nullable<Text>,
        atype -> Integer,
        status -> Integer,
        wait_time_days -> Integer,
        recovery_initiated_at -> Nullable<Timestamp>,
        last_notification_at -> Nullable<Timestamp>,
        updated_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    event (uuid) {
        uuid -> Text,
        event_type -> Integer,
        user_uuid -> Nullable<Text>,
        org_uuid -> Nullable<Text>,
        cipher_uuid -> Nullable<Text>,
        collection_uuid -> Nullable<Text>,
        group_uuid -> Nullable<Text>,
        org_user_uuid -> Nullable<Text>,
        act_user_uuid -> Nullable<Text>,
        device_type -> Nullable<Integer>,
        ip_address -> Nullable<Text>,
        event_date -> Timestamp,
        policy_uuid -> Nullable<Text>,
        provider_uuid -> Nullable<Text>,
        provider_user_uuid -> Nullable<Text>,
        provider_org_uuid -> Nullable<Text>,
    }
}

diesel::table! {
    favorites (user_uuid, cipher_uuid) {
        user_uuid -> Text,
        cipher_uuid -> Text,
    }
}

diesel::table! {
    folders (uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        name -> Text,
    }
}

diesel::table! {
    folders_ciphers (cipher_uuid, folder_uuid) {
        cipher_uuid -> Text,
        folder_uuid -> Text,
    }
}

diesel::table! {
    groups (uuid) {
        uuid -> Text,
        organizations_uuid -> Text,
        name -> Text,
        access_all -> Bool,
        external_id -> Nullable<Text>,
        creation_date -> Timestamp,
        revision_date -> Timestamp,
    }
}

diesel::table! {
    groups_users (rowid) {
        rowid -> Integer,
        groups_uuid -> Text,
        users_organizations_uuid -> Text,
    }
}

diesel::table! {
    invitations (email) {
        email -> Text,
    }
}

diesel::table! {
    org_policies (uuid) {
        uuid -> Text,
        org_uuid -> Text,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
    }
}

diesel::table! {
    organization_api_key (uuid, org_uuid) {
        uuid -> Text,
        org_uuid -> Text,
        atype -> Integer,
        api_key -> Text,
        revision_date -> Timestamp,
    }
}

diesel::table! {
    organizations (uuid) {
        uuid -> Text,
        name -> Text,
        billing_email -> Text,
        private_key -> Nullable<Text>,
        public_key -> Nullable<Text>,
    }
}

diesel::table! {
    sends (uuid) {
        uuid -> Text,
        user_uuid -> Nullable<Text>,
        organization_uuid -> Nullable<Text>,
        name -> Text,
        notes -> Nullable<Text>,
        atype -> Integer,
        data -> Text,
        akey -> Text,
        password_hash -> Nullable<Binary>,
        password_salt -> Nullable<Binary>,
        password_iter -> Nullable<Integer>,
        max_access_count -> Nullable<Integer>,
        access_count -> Integer,
        creation_date -> Timestamp,
        revision_date -> Timestamp,
        expiration_date -> Nullable<Timestamp>,
        deletion_date -> Timestamp,
        disabled -> Bool,
        hide_email -> Nullable<Bool>,
    }
}

diesel::table! {
    twofactor (uuid) {
        uuid -> Text,
        user_uuid -> Text,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
        last_used -> Integer,
    }
}

diesel::table! {
    twofactor_duo_ctx (state) {
        state -> Text,
        user_email -> Text,
        nonce -> Text,
        exp -> Integer,
    }
}

diesel::table! {
    twofactor_incomplete (user_uuid, device_uuid) {
        user_uuid -> Text,
        device_uuid -> Text,
        device_name -> Text,
        login_time -> Timestamp,
        ip_address -> Text,
        device_type -> Integer,
    }
}

diesel::table! {
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
        verified_at -> Nullable<Timestamp>,
        last_verifying_at -> Nullable<Timestamp>,
        login_verify_count -> Integer,
        email_new -> Nullable<Text>,
        email_new_token -> Nullable<Text>,
        enabled -> Bool,
        stamp_exception -> Nullable<Text>,
        api_key -> Nullable<Text>,
        avatar_color -> Nullable<Text>,
        client_kdf_memory -> Nullable<Integer>,
        client_kdf_parallelism -> Nullable<Integer>,
        external_id -> Nullable<Text>,
    }
}

diesel::table! {
    users_collections (user_uuid, collection_uuid) {
        user_uuid -> Text,
        collection_uuid -> Text,
        read_only -> Bool,
        hide_passwords -> Bool,
        manage -> Bool,
    }
}

diesel::table! {
    users_organizations (uuid) {
        uuid -> Text,
        user_uuid -> Text,
        org_uuid -> Text,
        access_all -> Bool,
        akey -> Text,
        status -> Integer,
        atype -> Integer,
        reset_password_key -> Nullable<Text>,
        external_id -> Nullable<Text>,
    }
}

diesel::table! {
    web_authn_credentials (uuid) {
        uuid -> Text,
        user_uuid -> Text,
        name -> Text,
        credential -> Text,
        supports_prf -> Bool,
        encrypted_user_key -> Text,
        encrypted_public_key -> Text,
        encrypted_private_key -> Text,
    }
}

diesel::joinable!(attachments -> ciphers (cipher_uuid));
diesel::joinable!(auth_requests -> organizations (organization_uuid));
diesel::joinable!(auth_requests -> users (user_uuid));
diesel::joinable!(ciphers -> organizations (organization_uuid));
diesel::joinable!(ciphers -> users (user_uuid));
diesel::joinable!(ciphers_collections -> ciphers (cipher_uuid));
diesel::joinable!(ciphers_collections -> collections (collection_uuid));
diesel::joinable!(collections -> organizations (org_uuid));
diesel::joinable!(collections_groups -> collections (collections_uuid));
diesel::joinable!(collections_groups -> groups (groups_uuid));
diesel::joinable!(devices -> users (user_uuid));
diesel::joinable!(favorites -> ciphers (cipher_uuid));
diesel::joinable!(favorites -> users (user_uuid));
diesel::joinable!(folders -> users (user_uuid));
diesel::joinable!(folders_ciphers -> ciphers (cipher_uuid));
diesel::joinable!(folders_ciphers -> folders (folder_uuid));
diesel::joinable!(groups -> organizations (organizations_uuid));
diesel::joinable!(groups_users -> groups (groups_uuid));
diesel::joinable!(groups_users -> users_organizations (users_organizations_uuid));
diesel::joinable!(org_policies -> organizations (org_uuid));
diesel::joinable!(organization_api_key -> organizations (org_uuid));
diesel::joinable!(sends -> organizations (organization_uuid));
diesel::joinable!(sends -> users (user_uuid));
diesel::joinable!(twofactor -> users (user_uuid));
diesel::joinable!(twofactor_incomplete -> users (user_uuid));
diesel::joinable!(users_collections -> collections (collection_uuid));
diesel::joinable!(users_collections -> users (user_uuid));
diesel::joinable!(users_organizations -> organizations (org_uuid));
diesel::joinable!(users_organizations -> users (user_uuid));
diesel::joinable!(web_authn_credentials -> users (user_uuid));

diesel::allow_tables_to_appear_in_same_query!(
    attachments,
    auth_requests,
    ciphers,
    ciphers_collections,
    collections,
    collections_groups,
    devices,
    emergency_access,
    event,
    favorites,
    folders,
    folders_ciphers,
    groups,
    groups_users,
    invitations,
    org_policies,
    organization_api_key,
    organizations,
    sends,
    twofactor,
    twofactor_duo_ctx,
    twofactor_incomplete,
    users,
    users_collections,
    users_organizations,
    web_authn_credentials,
);
