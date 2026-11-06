-- PROPOSAL ONLY: deploy after authorization and a recovery plan.
BEGIN;
DROP FUNCTION ti_security.trusted_list_relationships(text,text,text,integer,integer);
DROP FUNCTION ti_security.trusted_traverse_relationships(text,text,integer,text[],integer,integer);
COMMIT;
