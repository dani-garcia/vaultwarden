ALTER TABLE organizations
  ADD COLUMN private_key TEXT;

ALTER TABLE organizations
  ADD COLUMN public_key TEXT;
