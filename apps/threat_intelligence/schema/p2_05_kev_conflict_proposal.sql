-- PROPOSAL ONLY: apply after P2-04; requires separate owner/security approval.
BEGIN;
CREATE TABLE ti_kev.source_conflict (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  origin text NOT NULL,
  previous_snapshot_id bigint NOT NULL,
  candidate_content_sha256 text NOT NULL,
  observed_at timestamptz NOT NULL,
  FOREIGN KEY (previous_snapshot_id,origin) REFERENCES ti_kev.snapshot(id,origin),
  FOREIGN KEY (origin,candidate_content_sha256) REFERENCES ti_kev.source_blob(origin,content_sha256),
  UNIQUE(origin,previous_snapshot_id,candidate_content_sha256)
);
REVOKE ALL ON ti_kev.source_conflict FROM PUBLIC;
REVOKE ALL ON SEQUENCE ti_kev.source_conflict_id_seq FROM PUBLIC;
COMMIT;
