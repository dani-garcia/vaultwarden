-- Key rotations before this kept the id of the old user key, so every new
-- cipher was refused from then on. Stale ids can't be told apart, so clear
-- all of them; clients record their current key's id again when it's empty.
UPDATE users SET key_id = NULL;
