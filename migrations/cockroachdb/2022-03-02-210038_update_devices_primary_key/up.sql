-- First remove the previous primary key
ALTER TABLE devices DROP CONSTRAINT devices_pkey;
-- Add a new combined one
ALTER TABLE devices ADD PRIMARY KEY (uuid, user_uuid);
