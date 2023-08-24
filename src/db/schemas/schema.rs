table! {
    attachments (id) {
        id -> Text,
        cipher_uuid -> Text,
        file_name -> Text,
        file_size -> Integer,
        akey -> Nullable<Text>,
    }
}

table! {
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
    }
}

table! {
    ciphers_collections (cipher_uuid, collection_uuid) {
        cipher_uuid -> Text,
        collection_uuid -> Text,
    }
}

table! {
    collections (uuid) {
        uuid -> Text,
        org_uuid -> Text,
        name -> Text,
        external_id -> Nullable<Text>,
    }
}

table! {
    devices (uuid, user_uuid) {
        uuid -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        user_uuid -> Text,
        name -> Text,
        atype -> Integer,
        push_uuid -> Nullable<Text>,
        push_token -> Nullable<Text>,
        refresh_token -> Text,
        twofactor_remember -> Nullable<Text>,
    }
}

table! {
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

table! {
    favorites (user_uuid, cipher_uuid) {
        user_uuid -> Text,
        cipher_uuid -> Text,
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
    folders_ciphers (cipher_uuid, folder_uuid) {
        cipher_uuid -> Text,
        folder_uuid -> Text,
    }
}

table! {
    invitations (email) {
        email -> Text,
    }
}

table! {
    org_policies (uuid) {
        uuid -> Text,
        org_uuid -> Text,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
    }
}

table! {
    organizations (uuid) {
        uuid -> Text,
        name -> Text,
        billing_email -> Text,
        private_key -> Nullable<Text>,
        public_key -> Nullable<Text>,
    }
}

table! {
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

table! {
    twofactor (uuid) {
        uuid -> Text,
        user_uuid -> Text,
        atype -> Integer,
        enabled -> Bool,
        data -> Text,
        last_used -> Integer,
    }
}

table! {
    twofactor_incomplete (user_uuid, device_uuid) {
        user_uuid -> Text,
        device_uuid -> Text,
        device_name -> Text,
        login_time -> Timestamp,
        ip_address -> Text,
    }
}

table! {
    users (uuid) {
        uuid -> Text,
        enabled -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        verified_at -> Nullable<Timestamp>,
        last_verifying_at -> Nullable<Timestamp>,
        login_verify_count -> Integer,
        email -> Text,
        email_new -> Nullable<Text>,
        email_new_token -> Nullable<Text>,
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
        stamp_exception -> Nullable<Text>,
        equivalent_domains -> Text,
        excluded_globals -> Text,
        client_kdf_type -> Integer,
        client_kdf_iter -> Integer,
        client_kdf_memory -> Nullable<Integer>,
        client_kdf_parallelism -> Nullable<Integer>,
        api_key -> Nullable<Text>,
        avatar_color -> Nullable<Text>,
        external_id -> Nullable<Text>,
    }
}

table! {
    users_collections (user_uuid, collection_uuid) {
        user_uuid -> Text,
        collection_uuid -> Text,
        read_only -> Bool,
        hide_passwords -> Bool,
    }
}

table! {
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

table! {
    organization_api_key (uuid, org_uuid) {
        uuid -> Text,
        org_uuid -> Text,
        atype -> Integer,
        api_key -> Text,
        revision_date -> Timestamp,
    }
}

table! {
    emergency_access (uuid) {
        uuid -> Text,
        grantor_uuid -> Text,
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

table! {
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

table! {
    groups_users (groups_uuid, users_organizations_uuid) {
        groups_uuid -> Text,
        users_organizations_uuid -> Text,
    }
}

table! {
    collections_groups (collections_uuid, groups_uuid) {
        collections_uuid -> Text,
        groups_uuid -> Text,
        read_only -> Bool,
        hide_passwords -> Bool,
    }
}

table! {
    auth_requests  (uuid) {
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
joinable!(sends -> organizations (organization_uuid));
joinable!(sends -> users (user_uuid));
joinable!(twofactor -> users (user_uuid));
joinable!(users_collections -> collections (collection_uuid));
joinable!(users_collections -> users (user_uuid));
joinable!(users_organizations -> organizations (org_uuid));
joinable!(users_organizations -> users (user_uuid));
joinable!(users_organizations -> ciphers (org_uuid));
joinable!(organization_api_key -> organizations (org_uuid));
joinable!(emergency_access -> users (grantor_uuid));
joinable!(groups -> organizations (organizations_uuid));
joinable!(groups_users -> users_organizations (users_organizations_uuid));
joinable!(groups_users -> groups (groups_uuid));
joinable!(collections_groups -> collections (collections_uuid));
joinable!(collections_groups -> groups (groups_uuid));
joinable!(event -> users_organizations (uuid));
joinable!(auth_requests -> users (user_uuid));

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
    sends,
    twofactor,
    users,
    users_collections,
    users_organizations,
    organization_api_key,
    emergency_access,
    groups,
    groups_users,
    collections_groups,
    event,
    auth_requests,
);
