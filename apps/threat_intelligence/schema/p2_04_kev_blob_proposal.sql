-- PROPOSAL ONLY: apply after P2-03. Captures unmodified public source bytes.
BEGIN;
CREATE TABLE ti_kev.source_blob (
  origin text NOT NULL CHECK (origin IN ('FETCHED_FROM_GITHUB_CISA_REPO','EXPERIMENTAL_DEMO_DATA_ONLY')),
  content_sha256 text NOT NULL,
  blob_sha text NOT NULL,
  source_bytes bytea NOT NULL CHECK (octet_length(source_bytes) <= 3000000),
  PRIMARY KEY(origin,content_sha256),
  UNIQUE(origin,blob_sha)
);
REVOKE ALL ON ti_kev.source_blob FROM PUBLIC;
COMMIT;
