UPDATE users
SET totp_secret = (
    SELECT twofactor.data FROM twofactor
    WHERE twofactor.type = 0 
    AND twofactor.user_uuid = users.uuid
);

DROP TABLE twofactor;