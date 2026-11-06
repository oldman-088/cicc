-- PROPOSAL ONLY. Isolated public-feed storage; no shared host migration applied.
BEGIN;
CREATE SCHEMA ti_kev;
REVOKE ALL ON SCHEMA ti_kev FROM PUBLIC;
CREATE TABLE ti_kev.snapshot (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  origin text NOT NULL CHECK (origin IN ('FETCHED_FROM_GITHUB_CISA_REPO','EXPERIMENTAL_DEMO_DATA_ONLY')),
  source_url text NOT NULL,
  blob_sha text NOT NULL,
  content_sha256 text NOT NULL,
  released_at timestamptz NOT NULL,
  collected_at timestamptz NOT NULL,
  checked_at timestamptz NOT NULL,
  catalog_version text NOT NULL,
  entry_count integer NOT NULL CHECK (entry_count >= 0),
  UNIQUE (id, origin)
);
CREATE INDEX ti_kev_snapshot_origin_id ON ti_kev.snapshot(origin,id DESC);
CREATE TABLE ti_kev.revision (
  origin text NOT NULL,
  cve_id text NOT NULL,
  content_sha256 text NOT NULL,
  record jsonb NOT NULL,
  PRIMARY KEY (origin,cve_id,content_sha256)
);
CREATE TABLE ti_kev.snapshot_entry (
  snapshot_id bigint NOT NULL,
  origin text NOT NULL,
  cve_id text NOT NULL,
  content_sha256 text NOT NULL,
  PRIMARY KEY (snapshot_id,cve_id),
  FOREIGN KEY (snapshot_id,origin) REFERENCES ti_kev.snapshot(id,origin),
  FOREIGN KEY (origin,cve_id,content_sha256) REFERENCES ti_kev.revision(origin,cve_id,content_sha256)
);
REVOKE ALL ON ALL TABLES IN SCHEMA ti_kev FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA ti_kev FROM PUBLIC;
COMMIT;
