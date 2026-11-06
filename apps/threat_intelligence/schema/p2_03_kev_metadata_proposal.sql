-- PROPOSAL ONLY: apply after p2_02, independently owned. No shared deployment.
BEGIN;
CREATE TABLE ti_kev.catalog_metadata (
  snapshot_id bigint PRIMARY KEY REFERENCES ti_kev.snapshot(id),
  catalog jsonb NOT NULL CHECK (jsonb_typeof(catalog) = 'object')
);
REVOKE ALL ON ti_kev.catalog_metadata FROM PUBLIC;
COMMIT;
