ALTER TABLE twofactor_incomplete ADD COLUMN device_type INT4 NOT NULL DEFAULT 14; -- 14 = Unknown Browser
