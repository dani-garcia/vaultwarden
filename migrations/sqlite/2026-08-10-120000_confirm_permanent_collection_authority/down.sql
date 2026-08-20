-- Nothing to undo: this migration only asks for a decision, it never writes permissions. The
-- acknowledgement it consumes is deliberately not recreated -- a revert is not consent, and the next
-- upgrade has to ask again.
SELECT 1;
