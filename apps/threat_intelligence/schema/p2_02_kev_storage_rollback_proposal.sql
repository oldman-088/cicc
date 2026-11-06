-- PROPOSAL ONLY. DESTRUCTIVE: owner-approved backup/recovery required.
BEGIN;
DROP TABLE ti_kev.snapshot_entry;
DROP TABLE ti_kev.revision;
DROP TABLE ti_kev.snapshot;
DROP SCHEMA ti_kev;
COMMIT;
