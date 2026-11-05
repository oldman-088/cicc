"""B-06: observation-log compaction with an intact, verifiable digest chain.

The rule that makes compaction safe: folding reduces *rows*, never *evidence*.
Every digest stays in the chain, duplicates included, and a snapshot whose
chain does not verify is corruption, not a summary.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from vuln_intel.integration.observations import (
    CompactionReport,
    ImmutableObservationLog,
    Observation,
    compact_observations,
    digest_payload,
    verify_snapshot_chain,
)
from vuln_intel.schema import Origin

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def _obs(cve="CVE-2026-0001", source="nvd", at=T0, payload=None, tenant="t1",
         origin=Origin.LIVE) -> Observation:
    payload = payload if payload is not None else {"cve_id": cve, "v": str(at)}
    return Observation(
        tenant_id=tenant,
        cve=cve,
        source=source,
        source_ref=None,
        origin=origin,
        collected_at=at,
        payload=payload,
        digest=digest_payload(payload),
    )


class TestCompactObservations:
    def test_one_snapshot_per_tenant_cve_source(self):
        rows = [
            _obs(source="nvd", at=T0),
            _obs(source="osv", at=T0 + timedelta(minutes=1)),
            _obs(source="nvd", at=T0 + timedelta(minutes=2)),
        ]
        snapshots = compact_observations(rows)
        assert len(snapshots) == 2
        by_source = {s.source: s for s in snapshots}
        assert by_source["nvd"].observation_count == 2
        assert by_source["osv"].observation_count == 1

    def test_digest_chain_keeps_duplicates_and_order(self):
        same = {"cve_id": "CVE-2026-0001", "v": "same"}
        rows = [
            _obs(at=T0 + timedelta(minutes=5), payload=same),
            _obs(at=T0, payload={"cve_id": "CVE-2026-0001", "v": "first"}),
            _obs(at=T0 + timedelta(minutes=2), payload=same),
        ]
        (snap,) = compact_observations(rows)
        assert snap.observation_count == 3
        # ordered by collected_at: first, dup, dup — all three digests present
        assert snap.digest_chain == tuple(r.digest for r in sorted(rows, key=lambda r: (r.collected_at, r.digest)))
        assert snap.digest_chain[1] == snap.digest_chain[2]  # duplicate retained, not folded away
        assert snap.latest_digest == snap.digest_chain[-1]
        assert snap.first_collected_at == T0
        assert snap.last_collected_at == T0 + timedelta(minutes=5)

    def test_chain_digest_commits_to_the_whole_chain(self):
        rows = [_obs(at=T0 + timedelta(minutes=i)) for i in range(4)]
        (snap,) = compact_observations(rows)
        expected = hashlib.sha256("\n".join(snap.digest_chain).encode()).hexdigest()
        assert snap.chain_digest == expected
        assert verify_snapshot_chain(snap)

    def test_verify_fails_when_chain_is_tampered(self):
        rows = [_obs(at=T0), _obs(at=T0 + timedelta(minutes=1))]
        (snap,) = compact_observations(rows)
        tampered = type(snap)(
            tenant_id=snap.tenant_id, cve=snap.cve, source=snap.source,
            origin=snap.origin, observation_count=snap.observation_count,
            first_collected_at=snap.first_collected_at,
            last_collected_at=snap.last_collected_at,
            latest_digest=snap.latest_digest,
            digest_chain=(snap.digest_chain[0], "0" * 64),  # swapped middle digest
            payload=snap.payload,
            chain_digest=snap.chain_digest,  # the ORIGINAL commitment
        )
        assert not verify_snapshot_chain(tampered)

    def test_verify_fails_when_count_disagrees_with_chain_length(self):
        rows = [_obs(at=T0), _obs(at=T0 + timedelta(minutes=1))]
        (snap,) = compact_observations(rows)
        inflated = type(snap)(
            tenant_id=snap.tenant_id, cve=snap.cve, source=snap.source,
            origin=snap.origin, observation_count=5,
            first_collected_at=snap.first_collected_at,
            last_collected_at=snap.last_collected_at,
            latest_digest=snap.latest_digest,
            digest_chain=snap.digest_chain,
            payload=snap.payload,
        )
        assert not verify_snapshot_chain(inflated)

    def test_empty_input_compacts_to_empty(self):
        assert compact_observations([]) == ()


class TestLogCompaction:
    def test_compact_summarises_whole_log_and_leaves_rows_intact(self):
        log = ImmutableObservationLog()
        for i in range(5):
            log.append(_obs(at=T0 + timedelta(minutes=i)))
        log.append(_obs(source="osv", at=T0))
        report = log.compact()
        assert isinstance(report, CompactionReport)
        assert report.rows_before == 6
        assert report.rows_after == 2
        assert report.chains_verified
        # the append-only rows are the evidence: compaction changed nothing
        assert log.size == 6
        assert len(log.list_for(tenant_id="t1", cve="CVE-2026-0001")) == 6

    def test_snapshots_for_one_cve_excludes_other_cves(self):
        log = ImmutableObservationLog()
        log.append(_obs(at=T0))                                # CVE-2026-0001 / nvd
        log.append(_obs(cve="CVE-2026-0002", at=T0))            # other CVE
        log.append(_obs(source="osv", at=T0 + timedelta(minutes=1)))  # CVE-2026-0001 / osv
        snaps = log.snapshots_for(tenant_id="t1", cve="CVE-2026-0001")
        assert {s.source for s in snaps} == {"nvd", "osv"}
        assert all(s.cve == "CVE-2026-0001" for s in snaps)

    def test_idempotent_replay_compacts_identically(self):
        log = ImmutableObservationLog()
        for i in range(3):
            log.append(_obs(at=T0 + timedelta(minutes=i)))
        log.append(_obs(at=T0))  # duplicate digest: refused as duplicate, not double-counted
        r1 = log.compact()
        r2 = log.compact()
        assert r1.as_dict() == r2.as_dict()
        assert r1.rows_before == 3  # the duplicate append was a no-op

    def test_fixture_origin_is_preserved_in_snapshot(self):
        log = ImmutableObservationLog(allow_fixture=True)
        log.append(_obs(origin=Origin.FIXTURE))
        (snap,) = log.compact().snapshots
        assert snap.origin is Origin.FIXTURE
        assert snap.as_dict()["origin"] == "fixture"

    def test_compaction_report_serialises(self):
        log = ImmutableObservationLog()
        log.append(_obs(at=T0))
        log.append(_obs(at=T0 + timedelta(minutes=1)))
        import json

        payload = log.compact().as_dict()
        json.dumps(payload)  # must be JSON-safe
        assert payload["rows_before"] == 2
        assert payload["rows_after"] == 1
        assert payload["chains_verified"] is True
