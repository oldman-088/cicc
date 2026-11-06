"""The ASGI app driven through the real ASGI protocol: scope, receive, send.

Not through ``app.handle(scope)``, which would test a helper. These build an ASGI scope,
await ``app(scope, receive, send)``, and decode the messages a server would actually
receive. That is the difference between "the contract is implementable" and "this mounts".

The resolver is injected everywhere, which mirrors production: authentication is the
platform's job and this app only consumes its verdict.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest

from vuln_intel.integration.api import ApiError
from vuln_intel.integration.asgi import build_app
from vuln_intel.integration.sqlite_store import SQLiteVulnerabilityStore

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


# -- ASGI plumbing used by the tests ------------------------------------------
def run(coro):
    return asyncio.run(coro)


class Recorder:
    """A 'server' that records what the app sends."""

    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def send(self, message):
        self.messages.append(message)

    async def receive(self):
        return {"type": "http.request", "body": b"", "more_body": False}

    @property
    def status(self) -> int:
        return self.messages[0]["status"]

    @property
    def headers(self) -> dict[str, str]:
        return {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in self.messages[0]["headers"]
        }

    @property
    def body(self) -> dict:
        return json.loads(self.messages[-1]["body"].decode("utf-8"))


def scope(method="GET", path="/v1/vulnerabilities", query="", headers=None, scheme="http"):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query.encode("latin-1"),
        "headers": [(k.lower().encode(), v.encode("latin-1")) for k, v in (headers or {}).items()],
        "scheme": scheme,
    }


def call(app, **kwargs) -> Recorder:
    recorder = Recorder()
    run(app(scope(**kwargs), recorder.receive, recorder.send))
    return recorder


@pytest.fixture
def store(tmp_path):
    return SQLiteVulnerabilityStore(path=tmp_path / "asgi.db", allow_fixture=True)


def _seed(store, cve="CVE-2026-0001", severity="high", tenant="tenant-a"):
    store.upsert(
        tenant_id=tenant,
        cve=cve,
        entity={},
        details={"severity": severity, "kev": False},
        enrichment={"origin": "fixture"},
        provenance={"source": "nvd"},
        collected_at=NOW,
        dry_run=False,
    )


@pytest.fixture
def app(store):
    return build_app(store, resolve_tenant=lambda scope: "tenant-a")


class TestTheAsgiContract:
    def test_it_speaks_asgi3(self, app):
        """The callable signature a server requires: (scope, receive, send)."""
        recorder = Recorder()
        run(app(scope(), recorder.receive, recorder.send))
        assert recorder.messages[0]["type"] == "http.response.start"
        assert recorder.messages[-1]["type"] == "http.response.body"

    def test_a_successful_get_returns_json(self, store, app):
        _seed(store)
        recorder = call(app, path="/v1/vulnerabilities/CVE-2026-0001")
        assert recorder.status == 200
        assert recorder.headers["content-type"].startswith("application/json")
        assert recorder.body["data"]["cve"] == "CVE-2026-0001"
        assert recorder.body["data"]["severity"] == "high"

    def test_the_response_is_not_cacheable(self, app):
        """A VEX verdict must not be cached by an intermediary."""
        recorder = call(app)
        assert recorder.headers["cache-control"] == "no-store"
        assert recorder.headers["x-content-type-options"] == "nosniff"

    def test_content_length_matches_the_body(self, store, app):
        _seed(store)
        recorder = call(app, path="/v1/vulnerabilities/CVE-2026-0001")
        assert int(recorder.headers["content-length"]) == len(recorder.messages[-1]["body"])

    def test_head_returns_headers_and_no_body(self, store, app):
        _seed(store)
        recorder = call(app, method="HEAD", path="/v1/vulnerabilities/CVE-2026-0001")
        assert recorder.status == 200
        assert recorder.messages[-1]["body"] == b""

    def test_lifespan_startup_and_shutdown_are_accepted(self, app):
        """Uvicorn refuses to start an app that errors on lifespan."""
        events = iter(
            [
                {"type": "lifespan.startup"},
                {"type": "lifespan.shutdown"},
            ]
        )
        sent: list[dict] = []

        async def receive():
            return next(events)

        async def send(message):
            sent.append(message)

        run(app({"type": "lifespan"}, receive, send))
        assert [m["type"] for m in sent] == [
            "lifespan.startup.complete",
            "lifespan.shutdown.complete",
        ]


class TestRouting:
    def test_the_collection_route(self, store, app):
        _seed(store)
        recorder = call(app)
        assert recorder.status == 200
        assert len(recorder.body["data"]) == 1

    def test_it_works_under_a_mount_prefix(self, store):
        """A host mounting at /api/vuln-intel would otherwise 404 on everything."""
        mounted = build_app(store, resolve_tenant=lambda scope: "tenant-a")
        _seed(store)
        recorder = call(mounted, path="/api/vuln-intel/v1/vulnerabilities/CVE-2026-0001")
        assert recorder.status == 200
        assert recorder.body["data"]["cve"] == "CVE-2026-0001"

    def test_an_unknown_route_is_404(self, app):
        assert call(app, path="/v1/nonsense").status == 404

    def test_a_deeper_than_known_path_is_404(self, app):
        assert call(app, path="/v1/vulnerabilities/a/b").status == 404

    def test_a_write_method_is_405_not_400(self, app):
        """400 would say the body was malformed; there is no body a client could send."""
        recorder = call(app, method="POST")
        assert recorder.status == 405
        assert recorder.body["error"]["code"] == "method_not_allowed"

    def test_a_non_http_scope_is_refused(self, app):
        recorder = Recorder()
        run(app({"type": "websocket"}, recorder.receive, recorder.send))
        assert recorder.status == 404


class TestTenantScoping:
    def test_the_client_cannot_supply_a_tenant(self, store):
        """A tenant_id in the query string must be ignored, not honoured."""
        _seed(store, tenant="tenant-a")
        as_b = build_app(store, resolve_tenant=lambda scope: "tenant-b")
        recorder = call(as_b, query="tenant_id=tenant-a")
        assert recorder.status == 200
        assert recorder.body["data"] == []

    def test_a_resolver_that_returns_blank_is_401(self, store):
        _seed(store)
        blank = build_app(store, resolve_tenant=lambda scope: "   ")
        assert call(blank, path="/v1/vulnerabilities/CVE-2026-0001").status == 401

    def test_a_resolver_that_raises_an_api_error_is_mapped(self, store):
        def denied(scope):
            raise ApiError("unauthorized", "no token")

        app = build_app(store, resolve_tenant=denied)
        recorder = call(app)
        assert recorder.status == 401
        assert recorder.body["error"]["code"] == "unauthorized"

    def test_a_resolver_crash_does_not_leak_a_stack(self, store):
        def explode(scope):
            raise RuntimeError('secret dsn="postgres://user:pw@host/db"')

        app = build_app(store, resolve_tenant=explode)
        recorder = call(app)
        assert recorder.status == 503
        assert "pw" not in json.dumps(recorder.body)
        assert "RuntimeError" in recorder.body["error"]["message"]


class TestQueryHandling:
    def test_paging_works_over_asgi(self, store, app):
        for index in range(3):
            _seed(store, cve=f"CVE-2026-01{index:02d}")
        first = call(app, query="limit=2")
        assert len(first.body["data"]) == 2
        assert first.body["page"]["has_more"] is True
        cursor = first.body["page"]["next_cursor"]
        second = call(app, query=f"limit=2&cursor={cursor}")
        assert len(second.body["data"]) == 1
        assert second.body["page"]["has_more"] is False

    def test_a_duplicate_parameter_is_rejected(self, app):
        """?limit=1&limit=100 is ambiguous, and last-wins resolves it for the client."""
        recorder = call(app, query="limit=1&limit=100")
        assert recorder.status == 400
        assert "duplicate" in recorder.body["error"]["message"]

    def test_a_bad_limit_is_400(self, app):
        assert call(app, query="limit=abc").status == 400

    def test_an_oversized_limit_is_400(self, app):
        assert call(app, query="limit=100000").status == 400

    def test_a_bad_severity_filter_is_400(self, app):
        assert call(app, query="severity=catastrophic").status == 400

    def test_the_kev_filter_is_honoured(self, store, app):
        _seed(store, cve="CVE-2026-0201")
        store.upsert(
            tenant_id="tenant-a", cve="CVE-2026-0202", entity={},
            details={"severity": "high", "kev": True}, enrichment={"origin": "fixture"},
            provenance={"source": "cisa"}, collected_at=NOW, dry_run=False,
        )
        recorder = call(app, query="kev_only=true")
        assert [row["cve"] for row in recorder.body["data"]] == ["CVE-2026-0202"]


class TestHttpsEnforcement:
    def test_http_is_refused_when_https_is_required(self, store):
        strict = build_app(store, resolve_tenant=lambda s: "tenant-a", require_https=True)
        assert call(strict, scheme="http").status == 401

    def test_a_forwarded_https_header_is_honoured(self, store):
        strict = build_app(store, resolve_tenant=lambda s: "tenant-a", require_https=True)
        recorder = call(strict, scheme="http", headers={"x-forwarded-proto": "https"})
        assert recorder.status == 200


class TestItNeverLeaks:
    def test_a_store_failure_becomes_503_without_detail(self):
        class Broken:
            def list(self, **kwargs):
                raise RuntimeError("could not connect to db-primary.internal:5432")

            def find(self, **kwargs):
                raise RuntimeError("could not connect to db-primary.internal:5432")

        app = build_app(Broken(), resolve_tenant=lambda scope: "tenant-a")
        recorder = call(app)
        assert recorder.status == 503
        text = json.dumps(recorder.body)
        assert "db-primary" not in text
        assert "5432" not in text

    def test_a_malformed_cve_is_400_not_500(self, app):
        recorder = call(app, path="/v1/vulnerabilities/not-a-cve")
        assert recorder.status == 400


class TestThePackageStaysFrameworkFree:
    def test_the_package_does_not_import_a_web_framework(self):
        """The ASGI app must not drag uvicorn/starlette/fastapi into the dependency set.

        A host that already runs one of them should not get a second, and a host that
        runs none should not need one to mount this.
        """
        import subprocess
        import sys

        code = (
            "import sys; import vuln_intel.integration.asgi; "
            "banned = {'uvicorn','starlette','fastapi','starlette.applications'}; "
            "loaded = {m for m in sys.modules if m.split('.')[0] in banned}; "
            "print(','.join(sorted(loaded)))"
        )
        # argv is built here from literals plus sys.executable; there is no untrusted
        # input, which is what the bandit heuristics cannot see. S603 is suppressed for
        # this call specifically rather than for the file, so a future subprocess call
        # taking outside data still trips it.
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code], capture_output=True, text=True, cwd="."
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "", f"framework(s) imported: {result.stdout.strip()}"

    def test_the_demo_harness_imports_cleanly_without_a_framework(self):
        """scripts/serve_demo.py must import its own package symbols before uvicorn."""
        import ast
        import pathlib

        source = pathlib.Path("scripts/serve_demo.py").read_text()
        tree = ast.parse(source)
        # uvicorn must be imported inside main(), not at module scope, so the script is
        # importable (and testable) in an environment without it.
        top_level = {
            node.names[0].name
            for node in tree.body
            if isinstance(node, ast.Import)
        }
        assert "uvicorn" not in top_level


class TestInteropExportsAreServed:
    """The VEX/OpenVEX/SARIF adapters were tested and unreachable from the service.

    A downstream team that wanted our verdicts had no way to fetch them; the exporters
    could only be called from Python by someone who already held an AssessmentReport.
    These tests go through the HTTP surface, which is the difference between a library
    function and a capability.
    """

    def _seed_log4j(self, store, *, tenant="tenant-a"):
        from vuln_intel.integration.mapping import to_store_payload
        from vuln_intel.schema import (
            AffectedPackage,
            CveId,
            CvssScore,
            NormalizedVulnerability,
            Origin,
            Severity,
        )

        record = NormalizedVulnerability(
            cve=CveId.parse("CVE-2021-44228"),
            origin=Origin.FIXTURE,
            summary="RCE in Log4j2",
            affected=(
                AffectedPackage(
                    ecosystem="maven", name="log4j-core",
                    introduced="2.0.0", fixed="2.15.0",
                ),
            ),
            cvss=(
                CvssScore(
                    version="3.1", base_score=10.0, severity=Severity.CRITICAL,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", source="nvd",
                ),
            ),
            kev=True,
            sources=("nvd", "cisa-kev"),
        )
        payload = to_store_payload(record, tenant_id=tenant, collected_at=NOW)
        store.upsert(
            tenant_id=tenant, cve="CVE-2021-44228", entity=payload["entity"],
            details=payload["details"], enrichment=payload["enrichment"],
            provenance=payload["provenance"], collected_at=NOW, dry_run=False,
        )

    _INVENTORY = (
        '[{"ecosystem":"maven","name":"log4j-core","version":"2.14.1","asset":"payments"}]'
    )

    @staticmethod
    def _deps_query() -> str:
        from urllib.parse import urlencode

        return urlencode({"dependencies": TestInteropExportsAreServed._INVENTORY})

    def test_cyclonedx_vex_is_served_and_says_exploitable(self, store, app):
        """With an inventory, a KEV-listed affected package must read as exploitable.

        Without one there is no exposure evaluation and therefore no ``analysis`` block
        at all — the adjacent test pins that, because "no analysis" and "not affected"
        must never be confused.
        """
        self._seed_log4j(store)
        recorder = call(app, path="/v1/vulnerabilities/export/vex", query=self._deps_query())
        assert recorder.status == 200
        body = recorder.body
        assert body["meta"]["format"] == "vex"
        assert body["meta"]["record_count"] == 1
        assert body["meta"]["exposure_evaluated"] is True
        vulnerabilities = body["document"]["vulnerabilities"]
        assert any(v.get("analysis", {}).get("state") == "exploitable" for v in vulnerabilities)

    def test_openvex_is_served_with_a_legal_status(self, store, app):
        self._seed_log4j(store)
        recorder = call(app, path="/v1/vulnerabilities/export/openvex", query=self._deps_query())
        assert recorder.status == 200
        statements = recorder.body["document"]["statements"]
        assert statements
        assert all(s["status"] in {"affected", "not_affected", "fixed", "under_investigation"}
                   for s in statements)

    def test_sarif_is_served_with_a_version(self, store, app):
        self._seed_log4j(store)
        recorder = call(app, path="/v1/vulnerabilities/export/sarif", query=self._deps_query())
        assert recorder.status == 200
        document = recorder.body["document"]
        assert document["version"] == "2.1.0"
        assert document["runs"]

    def test_an_unknown_format_is_404(self, app):
        assert call(app, path="/v1/vulnerabilities/export/csv").status == 404

    def test_exports_are_tenant_scoped(self, store, app):
        """A second tenant must not receive another tenant's VEX statements."""
        self._seed_log4j(store, tenant="tenant-a")
        other = build_app(store, resolve_tenant=lambda scope: "tenant-b")
        recorder = call(other, path="/v1/vulnerabilities/export/openvex")
        assert recorder.status == 200
        assert recorder.body["document"]["statements"] == []
        assert recorder.body["meta"]["record_count"] == 0
        assert recorder.body["meta"]["empty"] is True

    def test_without_inventory_the_export_is_honest_about_it(self, store, app):
        """No inventory means exposure was never evaluated — say so, do not imply clean."""
        self._seed_log4j(store)
        recorder = call(app, path="/v1/vulnerabilities/export/vex")
        meta = recorder.body["meta"]
        assert meta["exposure_evaluated"] is False
        assert "CVE-2021-44228" in meta["unassessed"]

    def test_with_inventory_exposure_is_evaluated(self, store, app):
        self._seed_log4j(store)
        recorder = call(app, path="/v1/vulnerabilities/export/vex", query=self._deps_query())
        assert recorder.status == 200
        assert recorder.body["meta"]["exposure_evaluated"] is True

    def test_without_inventory_there_is_no_analysis_block(self, store, app):
        """`analysis: absent` must not be mistaken for `state: not_affected`."""
        self._seed_log4j(store)
        recorder = call(app, path="/v1/vulnerabilities/export/vex")
        for vulnerability in recorder.body["document"]["vulnerabilities"]:
            assert "analysis" not in vulnerability

    def test_malformed_inventory_json_is_400(self, app):
        recorder = call(app, path="/v1/vulnerabilities/export/vex", query="dependencies=notjson")
        assert recorder.status == 400

    def test_inventory_that_is_not_an_array_is_400(self, app):
        recorder = call(app, path="/v1/vulnerabilities/export/vex", query='dependencies={"a":1}')
        assert recorder.status == 400

    def test_a_row_without_origin_is_409_not_a_document(self, store, app):
        """A row we cannot faithfully rebuild must not become an empty verdict."""
        store.upsert(
            tenant_id="tenant-a", cve="CVE-2026-5001", entity={},
            details={"severity": "high"},  # no origin anywhere
            enrichment=None, provenance={"source": "x"},
            collected_at=NOW, dry_run=False,
        )
        recorder = call(app, path="/v1/vulnerabilities/export/vex")
        assert recorder.status == 409
        assert recorder.body["error"]["code"] == "stored_record_invalid"

    def test_pagination_is_followed_so_records_are_not_silently_dropped(self, store):
        """A capped single page produced a VEX that looked complete and was not.

        The handler used to call ``store.list(limit=500)`` once and throw the cursor
        away. A consumer reads a VEX as the complete set of verdicts, so a missing
        record is work silently deleted from someone's queue, with nothing in the
        document saying it is partial.

        The store here *ignores* the requested limit and returns two rows per call.
        Only a handler that follows ``next_cursor`` to exhaustion can report all five,
        so this fails against the old one-call implementation for the right reason
        rather than because a constant was small.
        """
        inner = store

        class _StingyStore:
            """A store that refuses to honour a large page, like a real one under load."""

            pages_served = 0

            def find(self, **kwargs):
                return inner.find(**kwargs)

            def list(self, *, tenant_id, limit, cursor=None, **kwargs):
                page, next_cursor = inner.list(
                    tenant_id=tenant_id, limit=min(limit, 2), cursor=cursor, **kwargs
                )
                type(self).pages_served += 1
                return page, next_cursor

            def upsert(self, **kwargs):
                return inner.upsert(**kwargs)

        for index in range(5):
            inner.upsert(
                tenant_id="tenant-a",
                cve=f"CVE-2026-{7000 + index}",
                entity={},
                details={"origin": "fixture"},
                enrichment={"origin": "fixture"},
                provenance={"source": "test"},
                collected_at=NOW,
                dry_run=False,
            )
        stingy = _StingyStore()
        app = build_app(stingy, resolve_tenant=lambda scope: "tenant-a")
        recorder = call(app, path="/v1/vulnerabilities/export/vex")

        assert recorder.status == 200
        ids = {v["id"] for v in recorder.body["document"]["vulnerabilities"]}
        assert len(ids) == 5, f"expected every record, got {sorted(ids)}"
        assert recorder.body["meta"]["record_count"] == 5
        assert _StingyStore.pages_served >= 3, "the cursor was not followed"

    def test_exceeding_the_ceiling_is_an_explicit_refusal(self, store, app):
        """Truncation must be loud: a partial VEX is indistinguishable from a full one."""
        from vuln_intel.integration import asgi as asgi_module

        original = asgi_module._EXPORT_MAX_RECORDS
        asgi_module._EXPORT_MAX_RECORDS = 1
        try:
            for index in range(3):
                store.upsert(
                    tenant_id="tenant-a",
                    cve=f"CVE-2026-{8000 + index}",
                    entity={},
                    details={"origin": "fixture"},
                    enrichment={"origin": "fixture"},
                    provenance={"source": "test"},
                    collected_at=NOW,
                    dry_run=False,
                )
            recorder = call(app, path="/v1/vulnerabilities/export/vex")
        finally:
            asgi_module._EXPORT_MAX_RECORDS = original
        assert recorder.status == 400
        assert "truncated" in recorder.body["error"]["message"]

    def test_the_export_is_deterministic_for_the_same_rows(self, store, app):
        """Two exports of unchanged data must not differ only by a timestamp id."""
        self._seed_log4j(store)
        first = call(app, path="/v1/vulnerabilities/export/openvex").body["document"]
        second = call(app, path="/v1/vulnerabilities/export/openvex").body["document"]
        assert [s["vulnerability"] for s in first["statements"]] == [
            s["vulnerability"] for s in second["statements"]
        ]
