-- DSQL preview can't add columns with constraints, dropping `NOT NULL DEFAULT FALSE` constraint
-- It appears Diesel will ensure the column has appropriate values when saving records.

ALTER TABLE users_collections
ADD COLUMN manage BOOLEAN;

ALTER TABLE collections_groups
ADD COLUMN manage BOOLEAN;
