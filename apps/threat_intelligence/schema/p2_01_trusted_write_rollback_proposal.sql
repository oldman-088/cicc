-- PROPOSAL ONLY: owner approval required. Withdraws the write entry point.
-- Actor mapping is retained for preservation and security review.
BEGIN;
DROP FUNCTION ti_security.trusted_create_relationship(text, jsonb);
COMMIT;
