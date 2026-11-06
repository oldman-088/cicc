"""The comparison utility, tested against the shapes the two sides actually produce.

The host rows in this file are not invented. They are the exact ``details`` dict that
``apps/api/app/connectors/nvd_import.py`` builds (read from
``origin/arena/da631853-cicc``), paired with ``nvd_catalog_records`` columns from
migration ``0011``. The package rows come from the real ``to_store_payload``. A test
that compared made-up shapes would prove nothing about the two systems in production.

The central guarantee — that this cannot modify either side — is tested structurally,
by inspecting the module's imports, not by asking it nicely.
"""

from __future__ import annotations

import json

import pytest

from vuln_intel.integration.comparison import (
    IDENTICAL,
    ORDERING,
    RECORD_CONFLICTING,
    RECORD_HOST_ONLY,
    RECORD_IDENTICAL,
    RECORD_PACKAGE_ONLY,
    RECORD_REPRESENTATION,
    RECORD_STALE,
    SEMANTIC,
    TIMESTAMP_FORMAT,
    compare_records,
)

_T0 = "2026-01-01T00:00:00+00:00"


def host_row(
    *,
    cve="CVE-2021-44228",
    published="2021-12-10T10:15:09.143",
    last_modified="2021-12-10T10:15:09.143",
    descriptions=None,
    last_collected_at=_T0,
    first_collected_at=_T0,
):
    """Exactly the shape ``nvd_import.py`` writes into ``nvd_catalog_records``.

    Note the host stores NVD's raw timestamp strings (no timezone) while this package
    stores ISO-8601 with an offset. That is a real, load-bearing difference and it is
    why timestamp-format comparison exists at all.
    """
    return {
        "cve_id": cve,
        "first_collected_at": first_collected_at,
        "last_collected_at": last_collected_at,
        "details": {
            "cve_id": cve,
            "published": published,
            "last_modified": last_modified,
            "status": "Analyzed",
            "descriptions": descriptions
            if descriptions is not None
            else [{"language": "en", "text": "Remote code execution in Log4j2"}],
            "source": "nvd",
            "source_reference": f"https://nvd.nist.gov/vuln/detail/{cve}",
        },
    }


def package_row(
    *,
    cve="CVE-2021-44228",
    published="2021-12-10T10:15:09.143",
    last_modified="2021-12-10T10:15:09.143",
    descriptions=None,
    collected_at=_T0,
    origin="live",
):
    """What this package writes: 14 keys, four of which overlap the host."""
    return {
        "tenant_id": "tenant-a",
        "cve": cve,
        "origin": origin,
        "collected_at": collected_at,
        "details": {
            "cve_id": cve,
            "published": published,
            "last_modified": last_modified,
            "descriptions": descriptions
            if descriptions is not None
            else [{"language": "en", "text": "Remote code execution in Log4j2"}],
            "origin": origin,
            "summary": "Remote code execution in Log4j2",
            "severity": "critical",
            "cvss": {"score": 10.0},
            "cwe": ["CWE-502"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "affected": [],
            "kev": True,
            "epss": {"score": 0.97},
            "cicc_enrichment": {"schema": "cicc.vuln_intel.v1"},
        },
    }


class TestTheFourSharedFieldsAreTheOnlyOnesCompared:
    def test_it_compares_exactly_the_documented_shared_fields(self):
        report = compare_records(host_rows=[host_row()], package_rows=[package_row()])
        compared = {f.name for f in report.records[0].fields}
        assert compared == {"cve_id", "published", "last_modified", "descriptions"}

    def test_a_field_only_one_side_writes_is_not_reported_as_a_disagreement(self):
        """`status` and `severity` differ by design; reporting them would be noise."""
        report = compare_records(host_rows=[host_row()], package_rows=[package_row()])
        assert report.records[0].status == RECORD_IDENTICAL
        assert "status" not in report.records[0].differing_fields
        assert "severity" not in report.records[0].differing_fields

    def test_the_report_states_what_was_compared(self):
        report = compare_records(host_rows=[], package_rows=[])
        assert set(report.as_dict()["compared_fields"]) == {
            "cve_id",
            "published",
            "last_modified",
            "descriptions",
        }


class TestIdenticalVersusFormatVersusSemantic:
    def test_byte_identical_values_are_identical(self):
        report = compare_records(host_rows=[host_row()], package_rows=[package_row()])
        assert all(f.verdict == IDENTICAL for f in report.records[0].fields)

    def test_the_same_instant_spelled_differently_is_a_format_difference(self):
        """`Z` vs `+00:00` is one instant. Calling it a conflict would be wrong."""
        report = compare_records(
            host_rows=[host_row(last_modified="2021-12-10T10:15:09Z")],
            package_rows=[package_row(last_modified="2021-12-10T10:15:09+00:00")],
        )
        record = report.records[0]
        field = next(f for f in record.fields if f.name == "last_modified")
        assert field.verdict == TIMESTAMP_FORMAT
        assert record.status == RECORD_REPRESENTATION
        assert record.status != RECORD_CONFLICTING

    def test_a_format_difference_is_not_counted_as_a_conflict(self):
        report = compare_records(
            host_rows=[host_row(published="2021-12-10T10:15:09Z")],
            package_rows=[package_row(published="2021-12-10T10:15:09+00:00")],
        )
        assert report.conflicting == 0
        assert report.representation_only == 1

    def test_the_host_stores_a_naive_stamp_and_the_package_an_aware_one(self):
        """Exactly the real asymmetry: NVD raw vs ISO-8601."""
        report = compare_records(
            host_rows=[host_row(published="2021-12-10T10:15:09.143")],
            package_rows=[package_row(published="2021-12-10T10:15:09.143+00:00")],
        )
        field = next(
            f for f in report.records[0].fields if f.name == "published"
        )
        assert field.verdict == TIMESTAMP_FORMAT

    def test_a_genuinely_different_timestamp_is_semantic(self):
        report = compare_records(
            host_rows=[host_row(published="2021-12-10T10:15:09Z")],
            package_rows=[package_row(published="2022-06-01T00:00:00Z")],
        )
        field = next(f for f in report.records[0].fields if f.name == "published")
        assert field.verdict == SEMANTIC
        assert "different instants" in (field.note or "")
        assert report.records[0].status == RECORD_CONFLICTING

    def test_different_description_text_is_semantic(self):
        report = compare_records(
            host_rows=[host_row(descriptions=[{"language": "en", "text": "one"}])],
            package_rows=[package_row(descriptions=[{"language": "en", "text": "two"}])],
        )
        field = next(f for f in report.records[0].fields if f.name == "descriptions")
        assert field.verdict == SEMANTIC

    def test_the_same_descriptions_in_another_order_are_not_semantic(self):
        left = [
            {"language": "en", "text": "a"},
            {"language": "es", "text": "b"},
        ]
        right = [
            {"language": "es", "text": "b"},
            {"language": "en", "text": "a"},
        ]
        report = compare_records(
            host_rows=[host_row(descriptions=left)],
            package_rows=[package_row(descriptions=right)],
        )
        field = next(f for f in report.records[0].fields if f.name == "descriptions")
        assert field.verdict == ORDERING
        assert report.conflicting == 0

    def test_an_unparseable_timestamp_is_reported_not_raised(self):
        report = compare_records(
            host_rows=[host_row(published="not a date")],
            package_rows=[package_row(published="not a date")],
        )
        field = next(f for f in report.records[0].fields if f.name == "published")
        assert "not a parseable timestamp" in (field.note or "")


class TestMissingStaleAndUnmatched:
    def test_a_record_only_the_host_has(self):
        report = compare_records(
            host_rows=[host_row()], package_rows=[]
        )
        assert report.records[0].status == RECORD_HOST_ONLY
        assert report.host_only == 1
        assert report.package_only == 0

    def test_a_record_only_the_package_has(self):
        report = compare_records(host_rows=[], package_rows=[package_row()])
        assert report.records[0].status == RECORD_PACKAGE_ONLY
        assert report.package_only == 1

    def test_an_unmatched_record_keeps_its_own_provenance(self):
        """A record with no counterpart still reports when it was collected."""
        comparison = compare_records(
            host_rows=[host_row(last_collected_at="2026-02-02T00:00:00+00:00")],
            package_rows=[],
        ).records[0]
        assert comparison.host_last_collected_at.startswith("2026-02-02")

    def test_a_stale_side_is_named(self):
        report = compare_records(
            host_rows=[host_row(last_collected_at="2025-01-01T00:00:00+00:00")],
            package_rows=[package_row(collected_at="2026-01-01T00:00:00+00:00")],
            stale_threshold_seconds=3600,
        )
        assert report.records[0].status == RECORD_STALE
        assert report.records[0].stale_side == "host"

    def test_staleness_is_not_assumed_without_a_threshold(self):
        """Two imports minutes apart are normal. The caller must say what is stale."""
        report = compare_records(
            host_rows=[host_row(last_collected_at="2025-01-01T00:00:00+00:00")],
            package_rows=[package_row(collected_at="2026-01-01T00:00:00+00:00")],
        )
        assert report.records[0].status == RECORD_IDENTICAL
        assert report.records[0].stale_side is None

    def test_a_real_disagreement_outranks_staleness(self):
        """Reporting a contradiction as merely stale would bury the contradiction."""
        report = compare_records(
            host_rows=[
                host_row(
                    last_collected_at="2025-01-01T00:00:00+00:00",
                    published="2021-01-01T00:00:00Z",
                )
            ],
            package_rows=[
                package_row(collected_at="2026-01-01T00:00:00+00:00",
                            published="2022-01-01T00:00:00Z")
            ],
            stale_threshold_seconds=60,
        )
        assert report.records[0].status == RECORD_CONFLICTING

    def test_rows_without_a_cve_are_unusable_not_silently_dropped(self):
        report = compare_records(
            host_rows=[{"details": {"published": "x"}}],
            package_rows=[{"details": {}}],
        )
        assert len(report.unusable) == 2
        assert {u["side"] for u in report.unusable} == {"host", "package"}

    def test_a_duplicate_is_reported_rather_than_overwritten(self):
        report = compare_records(
            host_rows=[host_row(), host_row()], package_rows=[]
        )
        assert any("duplicate" in u["reason"] for u in report.unusable)
        assert report.compared == 1


class TestItPreservesProvenance:
    def test_both_sides_timestamps_and_the_origin_are_kept(self):
        comparison = compare_records(
            host_rows=[host_row(first_collected_at="2026-01-01T00:00:00+00:00",
                                last_collected_at="2026-01-02T00:00:00+00:00")],
            package_rows=[package_row(collected_at="2026-01-02T00:00:00+00:00",
                                      origin="fixture")],
        ).records[0]
        assert comparison.host_first_collected_at.startswith("2026-01-01")
        assert comparison.host_last_collected_at.startswith("2026-01-02")
        assert comparison.package_collected_at.startswith("2026-01-02")
        # A fixture record must remain visibly a fixture in the comparison itself.
        assert comparison.package_origin == "fixture"


class TestTheReportIsMachineReadable:
    def test_it_serialises_without_a_custom_encoder(self):
        report = compare_records(
            host_rows=[host_row()],
            package_rows=[package_row()],
        )
        text = json.dumps(report.as_dict())
        parsed = json.loads(text)
        assert parsed["totals"]["compared"] == 1
        assert parsed["totals"]["identical"] == 1

    def test_the_totals_add_up_to_what_was_compared(self):
        report = compare_records(
            host_rows=[host_row(cve="CVE-1"), host_row(cve="CVE-2")],
            package_rows=[package_row(cve="CVE-2"), package_row(cve="CVE-3")],
        )
        totals = report.as_dict()["totals"]
        assert totals["compared"] == 3
        assert (
            totals["identical"]
            + totals["representation_only"]
            + totals["conflicting"]
            + totals["stale"]
            + totals["host_only"]
            + totals["package_only"]
            == totals["compared"]
        )


class TestItCannotWriteToEitherSide:
    """The read-only guarantee is structural, not a promise.

    Asking a function to promise it will not write is not evidence. This inspects what
    the module is *capable* of: no database driver, no ORM, no store, no connection
    factory. If any of those appear later, this fails and the guarantee is revisited.
    """

    def test_it_imports_nothing_that_can_write(self):
        import vuln_intel.integration.comparison as module

        banned = ("sqlite3", "psycopg", "sqlalchemy", "alembic", "store", "dbapi_store",
                  "sqlite_store")
        source = __import__("pathlib").Path(module.__file__).read_text(encoding="utf-8")
        for name in banned:
            assert f"import {name}" not in source, f"comparison.py imports {name}"
            assert f"from {name}" not in source, f"comparison.py imports from {name}"

    def test_its_public_api_takes_sequences_not_connections(self):
        import inspect

        signature = inspect.signature(compare_records)
        for name in signature.parameters:
            assert name not in ("conn", "connection", "session", "store", "db", "engine")

    def test_it_does_not_mutate_the_rows_it_is_given(self):
        host, package = host_row(), package_row()
        host_before, package_before = json.dumps(host, sort_keys=True), json.dumps(package, sort_keys=True)
        compare_records(host_rows=[host], package_rows=[package])
        assert json.dumps(host, sort_keys=True) == host_before
        assert json.dumps(package, sort_keys=True) == package_before

    def test_it_offers_no_reconcile_merge_or_apply_entry_point(self):
        import vuln_intel.integration.comparison as module

        for name in dir(module):
            lowered = name.lower()
            for verb in ("reconcile", "merge", "apply", "sync", "write", "update", "fix"):
                assert verb not in lowered, f"comparison.py exposes {name}"


class TestAgainstRealPackageOutput:
    """The package side built by ``to_store_payload``, not by hand."""

    @staticmethod
    def _real_package_row():
        from vuln_intel.integration.mapping import to_store_payload
        from vuln_intel.schema import CveId, NormalizedVulnerability, Origin

        record = NormalizedVulnerability(
            cve=CveId.parse("CVE-2021-44228"),
            origin=Origin.FIXTURE,
            summary="Remote code execution in Log4j2",
            # `details` is what becomes `descriptions[*].text`; without it the package
            # writes an empty description list and every comparison reports a
            # difference that has nothing to do with the timestamps under test.
            details="Remote code execution in Log4j2",
            sources=("nvd",),
        )
        payload = to_store_payload(record, tenant_id="tenant-a", collected_at=None)
        return {
            "cve": payload["cve"],
            "origin": payload["origin"],
            "collected_at": payload["collected_at"],
            "details": payload["details"],
        }

    def test_a_real_package_row_is_comparable(self):
        report = compare_records(
            host_rows=[host_row()], package_rows=[self._real_package_row()]
        )
        assert report.compared == 1
        assert report.unusable == []
        # The four shared fields are all present on the real output.
        assert {f.name for f in report.records[0].fields} == {
            "cve_id", "published", "last_modified", "descriptions"
        }

    def test_a_fixture_without_a_published_date_produces_null_not_a_guess(self):
        """Corrected in M51: this is a *fixture* artefact, not an ingestion defect.

        M48 recorded this as "the package drops NVD timestamps, so a reader asking
        when a CVE was published gets nothing". That was wrong, and the way it was
        wrong is worth keeping: the fixture ``NormalizedVulnerability`` was built
        without ``published=``, so ``to_source_details`` faithfully rendered the
        explicit null it was given. The real connector sets it — see
        ``test_the_real_nvd_parser_round_trips_all_four_shared_fields`` below.

        The behaviour still matters: a null on one side is reported as semantic, and
        the note says which side is missing the value rather than blaming the other.
        """
        report = compare_records(
            host_rows=[host_row()], package_rows=[self._real_package_row()]
        )
        record = report.records[0]
        detail = {f.name: f for f in record.fields}
        assert detail["published"].verdict == SEMANTIC
        assert "package records no value" in (detail["published"].note or "")

    def test_the_real_nvd_parser_round_trips_all_four_shared_fields(self):
        """The finding M48 got wrong, pinned properly.

        Built from an NVD response shape through the real ``_parse_entry``, not from a
        hand-assembled record. All four shared fields survive into the store payload,
        and the only remaining difference is timestamp spelling.
        """
        from datetime import datetime, timezone

        from vuln_intel.connectors.nvd import NvdConnector
        from vuln_intel.schema import Origin

        connector = NvdConnector.__new__(NvdConnector)
        connector.origin = Origin.FIXTURE
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        entry = {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2021-12-10T10:15:09.143",
                "vulnStatus": "Analyzed",
                # NVD's API says `lang`/`value`; the package normalises to the
                # host's `language`/`text` on the way out. Using the normalised
                # names here would test nothing, because the parser would not see
                # a description at all -- which is what happened the first time.
                "descriptions": [{"lang": "en", "value": "RCE in Log4j2"}],
            }
        }
        record = connector._parse_entry(
            entry, now, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        )
        from vuln_intel.integration.mapping import to_store_payload

        payload = to_store_payload(record, tenant_id="t", collected_at=now)
        details = payload["details"]

        # All four shared fields are present and non-null.
        for name in ("cve_id", "published", "last_modified", "descriptions"):
            assert details.get(name) not in (None, []), f"{name} lost in mapping"

        report = compare_records(
            host_rows=[host_row(descriptions=[{"language": "en", "text": "RCE in Log4j2"}])],
            package_rows=[
                {
                    "cve": payload["cve"],
                    "origin": payload["origin"],
                    "collected_at": payload["collected_at"],
                    "details": details,
                }
            ],
        )
        verdicts = {f.name: f.verdict for f in report.records[0].fields}
        assert verdicts["cve_id"] == IDENTICAL
        assert verdicts["descriptions"] == IDENTICAL
        # Spelling only: NVD writes no offset, this package writes +00:00.
        assert verdicts["published"] == TIMESTAMP_FORMAT
        assert verdicts["last_modified"] == TIMESTAMP_FORMAT
        assert report.conflicting == 0


class TestTheReadOnlyCommandLine:
    """The operator entry point, exercised end to end against real databases.

    A utility that is read-only only when imported by a test is not read-only. These
    tests run the script against real SQLite files and check that the files are
    unchanged afterwards, and that SQLite itself refuses writes on the connection it
    opens.
    """

    @staticmethod
    def _make_dbs(tmp_path):
        import sqlite3

        host = tmp_path / "host.db"
        conn = sqlite3.connect(host)
        conn.execute(
            "CREATE TABLE nvd_catalog_records "
            "(cve_id TEXT, details TEXT, first_collected_at TEXT, last_collected_at TEXT)"
        )
        conn.execute(
            "INSERT INTO nvd_catalog_records VALUES (?,?,?,?)",
            (
                "CVE-2021-44228",
                json.dumps(
                    {
                        "cve_id": "CVE-2021-44228",
                        "published": "2021-12-10T10:15:09.143",
                        "last_modified": "2021-12-10T10:15:09.143",
                        "descriptions": [{"language": "en", "text": "a"}],
                    }
                ),
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
        conn.close()

        package = tmp_path / "pkg.db"
        conn = sqlite3.connect(package)
        conn.execute(
            "CREATE TABLE vulnerability_record "
            "(cve TEXT, details TEXT, origin TEXT, collected_at TEXT)"
        )
        conn.execute(
            "INSERT INTO vulnerability_record VALUES (?,?,?,?)",
            (
                "CVE-2021-44228",
                json.dumps(
                    {
                        "cve_id": "CVE-2021-44228",
                        "published": "2021-12-10T10:15:09.143+00:00",
                        "last_modified": "2021-12-10T10:15:09.143+00:00",
                        "descriptions": [{"language": "en", "text": "a"}],
                    }
                ),
                "live",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
        conn.close()
        return host, package

    def _run(self, host, package, *extra):
        import subprocess
        import sys

        script = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "scripts"
            / "compare_sources.py"
        )
        # argv is built from tmp_path and this test file's own location; no shell,
        # no user input. S603 cannot see that, so it is suppressed explicitly rather
        # than silently.
        return subprocess.run(  # noqa: S603
            [sys.executable, str(script), "--host-db", str(host),
             "--package-db", str(package), *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_it_reports_a_format_difference_without_calling_it_a_conflict(self, tmp_path):
        host, package = self._make_dbs(tmp_path)
        result = self._run(host, package)
        assert result.returncode == 0, result.stderr
        totals = json.loads(result.stdout)["totals"]
        assert totals["representation_only"] == 1
        assert totals["conflicting"] == 0

    def test_it_exits_non_zero_on_a_genuine_disagreement(self, tmp_path):
        host, package = self._make_dbs(tmp_path)
        import sqlite3

        conn = sqlite3.connect(package)
        details = json.loads(
            conn.execute("SELECT details FROM vulnerability_record").fetchone()[0]
        )
        details["published"] = "2023-01-01T00:00:00+00:00"
        conn.execute(
            "UPDATE vulnerability_record SET details = ?", (json.dumps(details),)
        )
        conn.commit()
        conn.close()

        result = self._run(host, package)
        assert result.returncode == 1
        assert "disagree" in result.stderr

    def test_it_leaves_both_databases_untouched(self, tmp_path):
        host, package = self._make_dbs(tmp_path)
        before = {
            path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (host, package)
        }
        self._run(host, package)
        after = {
            path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (host, package)
        }
        assert before == after

    def test_it_offers_no_flag_that_could_change_either_side(self):
        import subprocess
        import sys

        script = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "scripts"
            / "compare_sources.py"
        )
        help_text = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.lower()
        for verb in ("--fix", "--apply", "--reconcile", "--merge", "--write", "--delete"):
            assert verb not in help_text

    def test_sqlite_itself_refuses_a_write_on_the_connection_it_opens(self, tmp_path):
        """The guarantee is enforced by the engine, not by our discipline."""
        import importlib.util

        script = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "scripts"
            / "compare_sources.py"
        )
        spec = importlib.util.spec_from_file_location("compare_sources_under_test", script)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        host, _ = self._make_dbs(tmp_path)
        conn = module._connect_read_only(str(host))
        import sqlite3

        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM nvd_catalog_records")
        conn.close()

    def test_an_empty_comparison_is_not_reported_as_success(self, tmp_path):
        """Exit 2, because "nothing compared" is not "everything agrees"."""
        import sqlite3

        empty = tmp_path / "empty.db"
        conn = sqlite3.connect(empty)
        conn.execute("CREATE TABLE nvd_catalog_records (cve_id TEXT, details TEXT, "
                     "first_collected_at TEXT, last_collected_at TEXT)")
        conn.execute("CREATE TABLE vulnerability_record (cve TEXT, details TEXT, "
                     "origin TEXT, collected_at TEXT)")
        conn.commit()
        conn.close()
        result = self._run(empty, empty)
        assert result.returncode == 2


class TestTheNullFieldInventory:
    """`published: None` is reported as its own finding, not buried in a verdict.

    M48 flagged this as "the package drops NVD timestamps". M51 traced it: the real
    connector does write them, and what I had seen was a fixture that never set the
    field. The inventory stays, because a genuine null is still worth naming — it just
    is not the systemic defect the first report described.
    """

    @staticmethod
    def _host():
        return host_row(published="2021-12-10T10:15:09.143")

    @staticmethod
    def _package_with_nulls():
        row = package_row()
        row["details"]["published"] = None
        row["details"]["last_modified"] = None
        return row

    def test_a_null_on_the_package_side_is_listed(self):
        report = compare_records(
            host_rows=[self._host()], package_rows=[self._package_with_nulls()]
        )
        missing = {n["field"]: n for n in report.null_fields}
        assert set(missing) == {"published", "last_modified"}
        assert missing["published"]["missing_side"] == "package"
        assert missing["published"]["host_value"] == "2021-12-10T10:15:09.143"
        assert missing["published"]["package_value"] is None

    def test_a_null_on_the_host_side_is_listed_too(self):
        row = host_row()
        row["details"]["published"] = None
        report = compare_records(host_rows=[row], package_rows=[package_row()])
        missing = {n["field"]: n for n in report.null_fields}
        assert missing["published"]["missing_side"] == "host"
        assert missing["published"]["package_value"] is not None

    def test_a_genuine_disagreement_is_not_listed_as_a_null(self):
        """Both sides have a value but they differ: that is a conflict, not a gap."""
        report = compare_records(
            host_rows=[host_row(published="2021-01-01T00:00:00Z")],
            package_rows=[package_row(published="2022-01-01T00:00:00Z")],
        )
        assert report.null_fields == []
        assert report.conflicting == 1

    def test_a_representation_difference_is_not_listed(self):
        report = compare_records(
            host_rows=[host_row(published="2021-12-10T10:15:09Z")],
            package_rows=[package_row(published="2021-12-10T10:15:09+00:00")],
        )
        assert report.null_fields == []

    def test_the_count_appears_in_the_totals(self):
        report = compare_records(
            host_rows=[self._host()], package_rows=[self._package_with_nulls()]
        )
        assert report.as_dict()["totals"]["null_fields"] == 2

    def test_the_inventory_survives_json(self):
        report = compare_records(
            host_rows=[self._host()], package_rows=[self._package_with_nulls()]
        )
        parsed = json.loads(json.dumps(report.as_dict()))
        assert len(parsed["null_fields"]) == 2
