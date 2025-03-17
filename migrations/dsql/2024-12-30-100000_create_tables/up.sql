CREATE TABLE attachments (
    id text NOT NULL PRIMARY KEY,
    cipher_uuid character varying(40) NOT NULL,
    file_name text NOT NULL,
    file_size bigint NOT NULL,
    akey text
);

CREATE TABLE auth_requests (
    uuid character(36) NOT NULL PRIMARY KEY,
    user_uuid character(36) NOT NULL,
    organization_uuid character(36),
    request_device_identifier character(36) NOT NULL,
    device_type integer NOT NULL,
    request_ip text NOT NULL,
    response_device_id character(36),
    access_code text NOT NULL,
    public_key text NOT NULL,
    enc_key text,
    master_password_hash text,
    approved boolean,
    creation_date timestamp without time zone NOT NULL,
    response_date timestamp without time zone,
    authentication_date timestamp without time zone
);

CREATE TABLE ciphers (
    uuid character varying(40) NOT NULL PRIMARY KEY,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    user_uuid character varying(40),
    organization_uuid character varying(40),
    atype integer NOT NULL,
    name text NOT NULL,
    notes text,
    fields text,
    data text NOT NULL,
    password_history text,
    deleted_at timestamp without time zone,
    reprompt integer,
    key text
);

CREATE TABLE ciphers_collections (
    cipher_uuid character varying(40) NOT NULL,
    collection_uuid character varying(40) NOT NULL,
    PRIMARY KEY (cipher_uuid, collection_uuid)
);

CREATE TABLE collections (
    uuid character varying(40) NOT NULL PRIMARY KEY,
    org_uuid character varying(40) NOT NULL,
    name text NOT NULL,
    external_id text
);

CREATE TABLE collections_groups (
    collections_uuid character varying(40) NOT NULL,
    groups_uuid character(36) NOT NULL,
    read_only boolean NOT NULL,
    hide_passwords boolean NOT NULL,
    PRIMARY KEY (collections_uuid, groups_uuid)
);

CREATE TABLE devices (
    uuid character varying(40) NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    user_uuid character varying(40) NOT NULL,
    name text NOT NULL,
    atype integer NOT NULL,
    push_token text,
    refresh_token text NOT NULL,
    twofactor_remember text,
    push_uuid text,
    PRIMARY KEY (uuid, user_uuid)
);

CREATE TABLE emergency_access (
    uuid character(36) NOT NULL PRIMARY KEY,
    grantor_uuid character(36),
    grantee_uuid character(36),
    email character varying(255),
    key_encrypted text,
    atype integer NOT NULL,
    status integer NOT NULL,
    wait_time_days integer NOT NULL,
    recovery_initiated_at timestamp without time zone,
    last_notification_at timestamp without time zone,
    updated_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL
);

CREATE TABLE event (
    uuid character(36) NOT NULL PRIMARY KEY,
    event_type integer NOT NULL,
    user_uuid character(36),
    org_uuid character(36),
    cipher_uuid character(36),
    collection_uuid character(36),
    group_uuid character(36),
    org_user_uuid character(36),
    act_user_uuid character(36),
    device_type integer,
    ip_address text,
    event_date timestamp without time zone NOT NULL,
    policy_uuid character(36),
    provider_uuid character(36),
    provider_user_uuid character(36),
    provider_org_uuid character(36)
);

CREATE TABLE favorites (
    user_uuid character varying(40) NOT NULL,
    cipher_uuid character varying(40) NOT NULL,
    PRIMARY KEY (user_uuid, cipher_uuid)
);

CREATE TABLE folders (
    uuid character varying(40) NOT NULL PRIMARY KEY,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    user_uuid character varying(40) NOT NULL,
    name text NOT NULL
);

CREATE TABLE folders_ciphers (
    cipher_uuid character varying(40) NOT NULL,
    folder_uuid character varying(40) NOT NULL,
    PRIMARY KEY (cipher_uuid, folder_uuid)
);

CREATE TABLE groups (
    uuid character(36) NOT NULL PRIMARY KEY,
    organizations_uuid character varying(40) NOT NULL,
    name character varying(100) NOT NULL,
    access_all boolean NOT NULL,
    external_id character varying(300),
    creation_date timestamp without time zone NOT NULL,
    revision_date timestamp without time zone NOT NULL
);

CREATE TABLE groups_users (
    groups_uuid character(36) NOT NULL,
    users_organizations_uuid character varying(36) NOT NULL,
    PRIMARY KEY (groups_uuid, users_organizations_uuid)
);

CREATE TABLE invitations (
    email text NOT NULL PRIMARY KEY
);

CREATE TABLE org_policies (
    uuid character(36) NOT NULL PRIMARY KEY,
    org_uuid character(36) NOT NULL,
    atype integer NOT NULL,
    enabled boolean NOT NULL,
    data text NOT NULL,
    UNIQUE (org_uuid, atype)
);

CREATE TABLE organization_api_key (
    uuid character(36) NOT NULL,
    org_uuid character(36) NOT NULL,
    atype integer NOT NULL,
    api_key character varying(255),
    revision_date timestamp without time zone NOT NULL,
    PRIMARY KEY (uuid, org_uuid)
);

CREATE TABLE organizations (
    uuid character varying(40) NOT NULL PRIMARY KEY,
    name text NOT NULL,
    billing_email text NOT NULL,
    private_key text,
    public_key text
);

CREATE TABLE sends (
    uuid character(36) NOT NULL PRIMARY KEY,
    user_uuid character(36),
    organization_uuid character(36),
    name text NOT NULL,
    notes text,
    atype integer NOT NULL,
    data text NOT NULL,
    akey text NOT NULL,
    password_hash bytea,
    password_salt bytea,
    password_iter integer,
    max_access_count integer,
    access_count integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    revision_date timestamp without time zone NOT NULL,
    expiration_date timestamp without time zone,
    deletion_date timestamp without time zone NOT NULL,
    disabled boolean NOT NULL,
    hide_email boolean
);

CREATE TABLE twofactor (
    uuid character varying(40) NOT NULL PRIMARY KEY,
    user_uuid character varying(40) NOT NULL,
    atype integer NOT NULL,
    enabled boolean NOT NULL,
    data text NOT NULL,
    last_used bigint DEFAULT 0 NOT NULL,
    UNIQUE (user_uuid, atype)
);

CREATE TABLE twofactor_duo_ctx (
    state character varying(64) NOT NULL PRIMARY KEY,
    user_email character varying(255) NOT NULL,
    nonce character varying(64) NOT NULL,
    exp bigint NOT NULL
);

CREATE TABLE twofactor_incomplete (
    user_uuid character varying(40) NOT NULL,
    device_uuid character varying(40) NOT NULL,
    device_name text NOT NULL,
    login_time timestamp without time zone NOT NULL,
    ip_address text NOT NULL,
    device_type integer DEFAULT 14 NOT NULL,
    PRIMARY KEY (user_uuid, device_uuid)
);

CREATE TABLE users (
    uuid character varying(40) NOT NULL PRIMARY KEY,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    email text NOT NULL UNIQUE,
    name text NOT NULL,
    password_hash bytea NOT NULL,
    salt bytea NOT NULL,
    password_iterations integer NOT NULL,
    password_hint text,
    akey text NOT NULL,
    private_key text,
    public_key text,
    totp_secret text,
    totp_recover text,
    security_stamp text NOT NULL,
    equivalent_domains text NOT NULL,
    excluded_globals text NOT NULL,
    client_kdf_type integer DEFAULT 0 NOT NULL,
    client_kdf_iter integer DEFAULT 100000 NOT NULL,
    verified_at timestamp without time zone,
    last_verifying_at timestamp without time zone,
    login_verify_count integer DEFAULT 0 NOT NULL,
    email_new character varying(255) DEFAULT NULL::character varying,
    email_new_token character varying(16) DEFAULT NULL::character varying,
    enabled boolean DEFAULT true NOT NULL,
    stamp_exception text,
    api_key text,
    avatar_color text,
    client_kdf_memory integer,
    client_kdf_parallelism integer,
    external_id text
);

CREATE TABLE users_collections (
    user_uuid character varying(40) NOT NULL,
    collection_uuid character varying(40) NOT NULL,
    read_only boolean DEFAULT false NOT NULL,
    hide_passwords boolean DEFAULT false NOT NULL,
    PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE users_organizations (
    uuid character varying(40) NOT NULL PRIMARY KEY,
    user_uuid character varying(40) NOT NULL,
    org_uuid character varying(40) NOT NULL,
    access_all boolean NOT NULL,
    akey text NOT NULL,
    status integer NOT NULL,
    atype integer NOT NULL,
    reset_password_key text,
    external_id text,
    UNIQUE (user_uuid, org_uuid)
);