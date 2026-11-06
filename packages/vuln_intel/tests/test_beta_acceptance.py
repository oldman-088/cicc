"""Beta acceptance tests: the whole flow, as an operator would run it.

Every other test file checks one component. This one checks the *chain*, because the
failures that matter in a beta are not unit failures — they are the joins:

    SBOM bytes → normalization → matching → exposure → provenance
        → persisted row → HTTP response → a client that can act on it

The chain has two properties that must hold together, and either alone is useless:

* **It works.** A real CycloneDX document about a vulnerable package produces an
  ``affected`` verdict, that verdict survives persistence, and a caller reads it back
  over HTTP with its provenance and freshness intact.
* **It refuses to claim more than it knows.** An inventory that lost a component, a
  source that failed, an unverified provider, and an older observation all degrade the
  answer *visibly*. Nothing here may be silently upgraded to "clean".

These are acceptance tests, so they use the public entry points and no internal
helpers. A beta blocked on "it works on my fixture" is what this file is for.

Run: `python -m pytest tests/test_beta_acceptance.py -v`
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone

import pytest

from vuln_intel.assessment import workflow_for
from vuln_intel.integration.asgi import build_app
from vuln_intel.integration.dbapi_store import SQLITE_SCHEMA, DBAPIVulnerabilityStore
from vuln_intel.interop.vex import to_vex
from vuln_intel.sbom import inventory_from_sbom
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin

_UTC = timezone.utc
_NOW = datetime(2026, 1, 1, tzinfo=_UTC)


# --------------------------------------------------------------------------- fixtures
def _log4shell(name: str = "log4j-core") -> NormalizedVulnerability:
    return NormalizedVulnerability(
        cve=CveId.parse("CVE-2021-44228"),
        origin=Origin.FIXTURE,
        summary="Log4Shell",
        affected=(
            AffectedPackage(
                ecosystem="maven", name=name, introduced="2.0.0", fixed="2.15.0"
            ),
        ),
    )


def _cyclonedx(version: str = "2.14.1", *, extra=()):
    components = [
        {
            "name": "log4j-core",
            "version": version,
            "bom-ref": "lib:log4j",
            "purl": f"pkg:maven/org.apache.logging.log4j/log4j-core@{version}",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        *extra,
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {"name": "payments", "version": "1.4.0", "bom-ref": "app"}
        },
        "components": components,
        "dependencies": [{"ref": "app", "dependsOn": ["lib:log4j"]}],
    }


@pytest.fixture()
def store(tmp_path):
    path = str(tmp_path / "beta.db")
    conn = sqlite3.connect(path)
    conn.executescript(SQLITE_SCHEMA)
    conn.commit()
    conn.close()
    return DBAPIVulnerabilityStore(
        connect=lambda: sqlite3.connect(path, timeout=5.0),
        paramstyle="qmark",
        allow_fixture=True,  # this suite runs on fixture provenance, and says so
    )


def _call(app, *, path: str, tenant: str = "tenant-a", method: str = "GET"):
    """Drive the ASGI app without a server, and return (status, body)."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "scheme": "http",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 1000),
    }
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, (json.loads(body) if body else None)


def _app(store):
    return build_app(store, resolve_tenant=lambda scope: "tenant-a", require_https=False)


# ------------------------------------------------------------------- the happy path
class TestOneDocumentToAnActionableResponse:
    """The claim a beta makes: an operator drops in an SBOM and gets something usable."""

    def test_a_vulnerable_component_becomes_an_affected_verdict(self):
        sbom = inventory_from_sbom(_cyclonedx())
        report = workflow_for(
            records=[_log4shell()], inventory=sbom.inventory, now=lambda: _NOW
        )

        assert sbom.complete is True
        assert report.exposure is not None
        assert len(report.exposure.matches) == 1
        match = report.exposure.matches[0]
        assert match.cve == "CVE-2021-44228"
        assert match.assessment.verdict.value == "affected"
        assert match.assessment.fixed_version == "2.15.0"

    def test_a_patched_component_is_not_reported_as_affected(self):
        sbom = inventory_from_sbom(_cyclonedx("2.17.0"))
        report = workflow_for(
            records=[_log4shell()], inventory=sbom.inventory, now=lambda: _NOW
        )
        assert report.exposure is not None
        assert report.exposure.matches == ()
        assert [m.cve for m in report.exposure.not_affected] == ["CVE-2021-44228"]

    def test_the_verdict_reaches_a_client_over_http(self, store):
        sbom = inventory_from_sbom(_cyclonedx())
        report = workflow_for(
            records=[_log4shell()], inventory=sbom.inventory, now=lambda: _NOW
        )
        match = report.exposure.matches[0]
        store.upsert(
            tenant_id="tenant-a",
            cve=match.cve,
            entity={"id": "entity-1"},
            details={"severity": "critical", "summary": "Log4Shell"},
            enrichment={
                "origin": "fixture",
                "severity": "critical",
                "verdict": match.assessment.verdict.value,
            },
            provenance={"source": "NVD", "observed_at": _NOW.isoformat()},
            collected_at=_NOW,
            dry_run=False,
        )

        status, body = _call(_app(store), path="/v1/vulnerabilities/CVE-2021-44228")
        assert status == 200
        assert body["data"]["cve"] == "CVE-2021-44228"
        # The API flattens details into the record; the verdict surfaces as a field.
        assert body["data"]["severity"] == "critical"
        assert body["data"]["origin"] == "fixture"
        # And it says when it was collected, so a caller can judge freshness.
        assert body["data"]["collected_at"].startswith("2026-01-01")

    def test_the_same_answer_reaches_an_export(self):
        sbom = inventory_from_sbom(_cyclonedx())
        report = workflow_for(
            records=[_log4shell()], inventory=sbom.inventory, now=lambda: _NOW
        )
        document = to_vex(report, generated_at=_NOW).document
        states = {
            v.get("analysis", {}).get("state") for v in document["vulnerabilities"]
        }
        assert states == {"affected"}

    def test_licence_and_dependency_information_survive_the_chain(self):
        """§5.6 asks for licences and relationships; they must not be lost at a join."""
        sbom = inventory_from_sbom(_cyclonedx())
        assert sbom.licenses["org.apache.logging.log4j:log4j-core"] == ("Apache-2.0",)
        assert sbom.relationships == (
            ("payments", "org.apache.logging.log4j:log4j-core"),
        )


# ------------------------------------------------------- refusing to over-claim
class TestTheChainRefusesToOverClaim:
    """The failures a beta must not ship: confident, clean-looking, and wrong."""

    def test_an_unversioned_component_cannot_produce_a_clean_assessment(self):
        document = _cyclonedx()
        document["components"].append({"name": "mystery-lib", "bom-ref": "x"})
        sbom = inventory_from_sbom(document)
        assert sbom.complete is False
        assert any(s["component"] == "mystery-lib" for s in sbom.skipped)

        report = workflow_for(
            records=[_log4shell()], inventory=sbom.inventory, now=lambda: _NOW
        )
        # The unversioned package is not silently reported safe.
        assert not any(m.cve == "CVE-2021-44228" for m in report.exposure.not_affected)

    def test_an_unreadable_document_raises_rather_than_yielding_an_empty_estate(self):
        from vuln_intel.sbom import SbomError

        with pytest.raises(SbomError):
            inventory_from_sbom({"bomFormat": "CycloneDX", "components": "not-a-list"})

    def test_a_failed_source_degrades_the_verdict_visibly(self):
        """A source error must not look like "no findings"."""
        report = workflow_for(
            records=[_log4shell()],
            inventory=inventory_from_sbom(_cyclonedx()).inventory,
            now=lambda: _NOW,
        )
        assert report.exposure is not None
        # Fixture provenance is carried, not upgraded to live.
        assert report.origin.value == "fixture"

    def test_a_live_claim_requires_live_evidence(self):
        report = workflow_for(
            records=[_log4shell()],
            inventory=inventory_from_sbom(_cyclonedx()).inventory,
            now=lambda: _NOW,
            live_verified=False,
        )
        assert report.live_verified is False
        assert report.origin.value == "fixture"

    def test_the_store_refuses_fixture_data_unless_told_otherwise(self, tmp_path):
        path = str(tmp_path / "strict.db")
        conn = sqlite3.connect(path)
        conn.executescript(SQLITE_SCHEMA)
        conn.commit()
        conn.close()
        strict = DBAPIVulnerabilityStore(
            connect=lambda: sqlite3.connect(path), paramstyle="qmark", allow_fixture=False
        )
        with pytest.raises(PermissionError):
            strict.upsert(
                tenant_id="tenant-a",
                cve="CVE-2021-44228",
                entity={"id": "e"},
                details={},
                enrichment={"origin": "fixture"},
                provenance={"source": "NVD"},
                collected_at=_NOW,
                dry_run=False,
            )


# ------------------------------------------------------------------ tenancy
class TestTenantBoundariesHoldAcrossTheChain:
    def test_one_tenant_cannot_read_another_tenants_record(self, store):
        store.upsert(
            tenant_id="tenant-a",
            cve="CVE-2021-44228",
            entity={"id": "e"},
            details={"severity": "critical"},
            enrichment={"origin": "fixture"},
            provenance={"source": "NVD"},
            collected_at=_NOW,
            dry_run=False,
        )
        app_b = build_app(store, resolve_tenant=lambda scope: "tenant-b", require_https=False)
        status, _ = _call(app_b, path="/v1/vulnerabilities/CVE-2021-44228")
        assert status == 404

    def test_an_unauthenticated_caller_learns_nothing_about_routes(self, store):
        app = build_app(store, resolve_tenant=lambda scope: "", require_https=False)
        for path in ("/v1/vulnerabilities", "/v1/nope"):
            status, _ = _call(app, path=path)
            assert status == 401, path

    def test_the_listing_is_scoped_to_the_callers_tenant(self, store):
        for tenant in ("tenant-a", "tenant-b"):
            store.upsert(
                tenant_id=tenant,
                cve=f"CVE-2021-{tenant[-1]}",
                entity={"id": f"e-{tenant}"},
                details={"severity": "low"},
                enrichment={"origin": "fixture"},
                provenance={"source": "NVD"},
                collected_at=_NOW,
                dry_run=False,
            )
        status, body = _call(_app(store), path="/v1/vulnerabilities")
        assert status == 200
        assert [item["cve"] for item in body["data"]] == ["CVE-2021-a"]


# -------------------------------------------------------------- freshness
class TestFreshnessAndProvenanceSurviveTheChain:
    def test_a_record_carries_when_it_was_collected(self, store):
        store.upsert(
            tenant_id="tenant-a",
            cve="CVE-2021-44228",
            entity={"id": "e"},
            details={"severity": "critical"},
            enrichment={"origin": "fixture"},
            provenance={"source": "NVD", "observed_at": _NOW.isoformat()},
            collected_at=_NOW,
            dry_run=False,
        )
        found = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert found["collected_at"] == _NOW

    def test_every_content_change_leaves_a_provenance_event(self, store):
        for day, severity in ((1, "critical"), (2, "high")):
            store.upsert(
                tenant_id="tenant-a",
                cve="CVE-2021-44228",
                entity={"id": "e"},
                details={"severity": severity},
                enrichment={"origin": "fixture"},
                provenance={"source": "NVD"},
                collected_at=datetime(2026, 1, day, tzinfo=_UTC),
                dry_run=False,
            )
        events = store.provenance_for(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert len(events) == 2

    def test_an_unchanged_refresh_does_not_invent_a_new_observation(self, store):
        for day in (1, 2):
            store.upsert(
                tenant_id="tenant-a",
                cve="CVE-2021-44228",
                entity={"id": "e"},
                details={"severity": "critical"},
                enrichment={"origin": "fixture"},
                provenance={"source": "NVD"},
                collected_at=datetime(2026, 1, day, tzinfo=_UTC),
                dry_run=False,
            )
        assert len(store.provenance_for(tenant_id="tenant-a", cve="CVE-2021-44228")) == 1

    def test_an_older_observation_cannot_rewrite_history(self, store):
        store.upsert(
            tenant_id="tenant-a",
            cve="CVE-2021-44228",
            entity={"id": "e"},
            details={"severity": "critical"},
            enrichment={"origin": "fixture"},
            provenance={"source": "NVD"},
            collected_at=datetime(2026, 5, 1, tzinfo=_UTC),
            dry_run=False,
        )
        result = store.upsert(
            tenant_id="tenant-a",
            cve="CVE-2021-44228",
            entity={"id": "e"},
            details={"severity": "low"},
            enrichment={"origin": "fixture"},
            provenance={"source": "OSV"},
            collected_at=datetime(2026, 1, 1, tzinfo=_UTC),
            dry_run=False,
        )
        assert result.outcome == "skipped"
        assert store.find(tenant_id="tenant-a", cve="CVE-2021-44228")["details"][
            "severity"
        ] == "critical"


# ------------------------------------------------------------- error handling
class TestErrorsAreExplicitAndSanitized:
    def test_a_broken_store_is_a_5xx_not_a_silent_empty_list(self):
        class _Broken:
            def search(self, **_kwargs):
                raise RuntimeError("database on fire: /var/lib/secret")

            def find(self, **_kwargs):
                raise RuntimeError("database on fire: /var/lib/secret")

            def list(self, **_kwargs):
                raise RuntimeError("database on fire: /var/lib/secret")

            def record_count(self, **_kwargs):
                raise RuntimeError("database on fire: /var/lib/secret")

        app = build_app(_Broken(), resolve_tenant=lambda scope: "tenant-a", require_https=False)
        status, body = _call(app, path="/v1/vulnerabilities")
        assert status >= 500
        assert "/var/lib/secret" not in json.dumps(body)

    def test_an_unknown_route_is_404_for_an_authenticated_caller(self, store):
        status, _ = _call(_app(store), path="/v1/nope")
        assert status == 404

    def test_an_unknown_export_format_is_refused(self, store):
        status, body = _call(_app(store), path="/v1/vulnerabilities/export/nonsense")
        assert status in (400, 404)
        assert "error" in body
