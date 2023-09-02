-- Create new auth_requests table with master_password_hash as nullable column
CREATE TABLE auth_requests_new (
    uuid                        TEXT NOT NULL PRIMARY KEY,
    user_uuid                   TEXT NOT NULL,
    organization_uuid           TEXT,
    request_device_identifier   TEXT NOT NULL,
    device_type                 INTEGER NOT NULL,
    request_ip                  TEXT NOT NULL,
    response_device_id          TEXT,
    access_code                 TEXT NOT NULL,
    public_key                  TEXT NOT NULL,
    enc_key                     TEXT,
    master_password_hash        TEXT,
    approved                    BOOLEAN,
    creation_date               DATETIME NOT NULL,
    response_date               DATETIME,
    authentication_date         DATETIME,
    FOREIGN KEY (user_uuid) REFERENCES users (uuid),
    FOREIGN KEY (organization_uuid) REFERENCES organizations (uuid)
);

-- Transfer current data to new table
INSERT INTO	auth_requests_new SELECT * FROM auth_requests;

-- Drop the old table
DROP TABLE auth_requests;

-- Rename the new table to the original name
ALTER TABLE auth_requests_new RENAME TO auth_requests;
