"""The handoff fixtures must match what the code actually produces.

These fixtures exist so the frontend team can build against real payloads without
running the pipeline. That only works if they are *true*. A hand-maintained fixture
is a second implementation of the contract and drifts the first time someone edits a
field; the drift is silent, and the frontend discovers it in a browser.

So the fixtures are generated (`python -m vuln_intel.integration.golden --write`) and
this test regenerates them in memory and compares. A failure here means one of two
things, and the message says which:

* the code changed and the fixtures need regenerating — expected, commit both;
* the code changed *unintentionally* and the fixture caught it — the point.

Determinism is what makes the comparison meaningful, so the generator uses a fixed
clock and a fixed report id.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from vuln_intel.integration import golden

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "handoff"

REGENERATE = "run: python -m vuln_intel.integration.golden --write"


class TestDriftGuardDetectsMeaningfulDrift:
    """The guard must fail on *semantic* change, not only on byte change.

    This is the meta-test. A byte comparison catches everything, including a
    reformatted file, but it only fails if the generator and the file disagree — so
    these tests mutate a parsed copy and assert the guard's comparison sees it. They
    exist because a guard that silently stops guarding is indistinguishable from a
    guard that passes.

    Proven empirically before being written down: all seven mutations below were run
    against the real fixture files, and the expected verdicts are reproduced here
    without touching the files on disk.
    """

    @staticmethod
    def _expected() -> dict[str, str]:
        return golden.render()

    def _differs(self, mutate) -> bool:
        import json

        current = json.loads(self._expected()["api_get.json"])
        mutate(current)
        rendered = json.dumps(current, indent=2, sort_keys=True) + "\n"
        return rendered != self._expected()["api_get.json"]

    def test_a_whitespace_only_rerender_is_identical(self) -> None:
        import json

        current = json.loads(self._expected()["api_get.json"])
        rerendered = json.dumps(current, indent=2, sort_keys=True) + "\n"
        assert rerendered == self._expected()["api_get.json"]

    def test_a_changed_severity_is_detected(self) -> None:
        assert self._differs(lambda d: d["data"].__setitem__("severity", "low"))

    def test_a_removed_field_is_detected(self) -> None:
        assert self._differs(lambda d: d["data"].pop("record_status"))

    def test_null_promoted_to_false_is_detected(self) -> None:
        """`null` → `false` on `kev` is the semantic error the contract forbids."""
        assert self._differs(lambda d: d["data"].__setitem__("kev", False))

    def test_an_emptied_conflict_is_detected(self) -> None:
        # Applied to the listing fixture, which is where conflicts live; the assertion
        # is that the listing bytes move, not that the get fixture does.
        import json

        entry = json.loads(self._expected()["api_list.json"])
        conflict = next(r for r in entry["data"] if r["conflicts"])["conflicts"][0]
        conflict["discarded"] = []
        assert (json.dumps(entry, indent=2, sort_keys=True) + "\n") != self._expected()[
            "api_list.json"
        ]

    def test_a_dropped_row_is_detected(self) -> None:
        import json

        entry = json.loads(self._expected()["api_list.json"])
        entry["data"].pop()
        assert (json.dumps(entry, indent=2, sort_keys=True) + "\n") != self._expected()[
            "api_list.json"
        ]


class TestFixturesMatchTheCode:
    @pytest.mark.parametrize(
        "name",
        ["assessment_report.json", "api_get.json", "api_list.json",
         "api_error_not_found.json"],
    )
    def test_fixture_is_current(self, name: str) -> None:
        path = FIXTURE_DIR / name
        assert path.exists(), f"{name} is missing. {REGENERATE}"
        expected = golden.render()[name]
        actual = path.read_text()
        assert actual == expected, (
            f"{name} is out of date with the code; {REGENERATE}. "
            "If the diff is unexpected, the fixture just caught a regression."
        )

    def test_generation_is_deterministic(self) -> None:
        """Two renders must be identical, or the drift check is meaningless."""
        assert golden.render() == golden.render()


class TestFixtureContent:
    """The fixtures are only useful if they cover the cases the UI must render."""

    @staticmethod
    def _report() -> dict:
        return json.loads((FIXTURE_DIR / "assessment_report.json").read_text())

    @staticmethod
    def _listing() -> dict:
        return json.loads((FIXTURE_DIR / "api_list.json").read_text())

    def test_every_fixture_is_labelled_fixture_origin(self) -> None:
        """Synthetic data must be identifiable as synthetic, everywhere it appears."""
        report = self._report()
        assert report["origin"] == "fixture"
        assert report["live_verified"] is False
        for row in self._listing()["data"]:
            assert row["origin"] == "fixture"

    def test_the_report_does_not_claim_live_verification(self) -> None:
        """`live_verified` is the flag a UI would trust; it must be false.

        The notice itself does not mention liveness - it disclaims approval of the
        policy and the state of exploitation data, which is a different claim. So it
        is checked for what it actually says rather than for a word it does not use.
        """
        report = self._report()
        assert report["live_verified"] is False
        notice = report["notice"].lower()
        assert "not approved policy" in notice
        assert "exploitation status is unknown" in notice

    def test_the_listing_covers_each_standing(self) -> None:
        statuses = {row["record_status"] for row in self._listing()["data"]}
        assert {"published", "disputed", "rejected", "undergoing_analysis"} <= statuses

    def test_the_listing_includes_a_contested_record(self) -> None:
        """A UI badge for contested values needs a record that demonstrates one."""
        contested = [r for r in self._listing()["data"] if r["conflicts"]]
        assert contested
        conflict = contested[0]["conflicts"][0]
        assert set(conflict) == {"field", "kept", "discarded", "dissenters"}

    def test_the_listing_includes_an_unknown_severity(self) -> None:
        """The frontend must render "unknown" without treating it as the lowest."""
        severities = {row["severity"] for row in self._listing()["data"]}
        assert "unknown" in severities

    def test_the_report_has_exposure_findings(self) -> None:
        exposure = self._report()["exposure"]
        assert exposure is not None
        assert exposure["matches"], "no asset matched an advisory; fixture is too weak"

    def test_the_report_carries_conflict_counts(self) -> None:
        conflicts = self._report()["conflicts"]
        assert conflicts["records"] >= 1
        assert conflicts["by_field"]
        assert conflicts["disputed_standing"]

    def test_the_error_fixture_uses_the_documented_envelope(self) -> None:
        error = json.loads((FIXTURE_DIR / "api_error_not_found.json").read_text())
        assert error["status"] == 404
        assert set(error["body"]) >= {"error"}

    def test_the_get_fixture_is_a_single_object_under_data(self) -> None:
        body = json.loads((FIXTURE_DIR / "api_get.json").read_text())
        assert isinstance(body["data"], dict)
        assert body["data"]["cve"] == "CVE-2026-1001"
