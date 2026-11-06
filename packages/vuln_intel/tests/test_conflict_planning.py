"""Conflict planning: what would resolve a disagreement, chosen by nobody.

The property that matters most is what this module refuses to do. A resolver would pick
a severity, write it, and quietly become the authority for a decision with legal
consequences. This plans; it does not decide. Several tests below exist only to assert
that it still does not.
"""

from __future__ import annotations

import json

import pytest

from vuln_intel.conflict_planning import (
    NEVER_AUTOMATIC,
    TIMESTAMP_FIELDS,
    NextStep,
    plan_conflict_resolution,
)


def _record(cve="CVE-2021-44228", **conflicts):
    return {"cve": cve, "conflicts": list(conflicts.get("items", ()))}


def _conflict(field="severity", kept="critical", discarded=("high",),
              dissenters=("osv",)):
    return {
        "field": field,
        "kept": kept,
        "discarded": discarded,
        "dissenters": dissenters,
    }


class TestItNeverResolvesAnything:
    def test_nothing_is_ever_reported_as_resolved(self):
        plan = plan_conflict_resolution([_record(items=[_conflict()])])
        assert plan.anything_resolved is False
        assert all(entry.resolved is False for entry in plan.entries)

    def test_every_entry_carries_a_next_step(self):
        plan = plan_conflict_resolution([_record(items=[_conflict()])])
        assert plan.entries[0].next_step
        assert plan.entries[0].rationale

    @pytest.mark.parametrize("field_name", NEVER_AUTOMATIC)
    def test_a_judgement_field_is_never_auto_choosable(self, field_name):
        """Severity, CVSS, KEV status: an automatic winner is not an option offered."""
        plan = plan_conflict_resolution(
            [_record(items=[_conflict(field=field_name)])]
        )
        assert plan.entries[0].next_step == NextStep.ANALYST_JUDGEMENT

    def test_a_judgement_conflict_offers_no_proposed_value(self):
        plan = plan_conflict_resolution([_record(items=[_conflict(field="severity")])])
        assert "proposed_value" not in plan.entries[0].evidence


class TestDeterminism:
    _RECORDS = [
        _record(cve="CVE-2021-0002", items=[_conflict(field="cvss")]),
        _record(cve="CVE-2021-0001", items=[_conflict(field="severity")]),
        _record(cve="CVE-2021-0003", items=[_conflict(field="kev", kept="true",
                                                     discarded=("false",))]),
    ]

    def test_the_same_input_twice_gives_identical_output(self):
        first = plan_conflict_resolution(self._RECORDS).as_dict()
        second = plan_conflict_resolution(self._RECORDS).as_dict()
        assert first == second

    def test_input_order_does_not_change_the_plan(self):
        """A caller iterating a set or a query without ORDER BY must not change it."""
        forwards = plan_conflict_resolution(self._RECORDS).as_dict()
        backwards = plan_conflict_resolution(list(reversed(self._RECORDS))).as_dict()
        assert forwards == backwards

    def test_entries_are_ordered_by_cve_then_field(self):
        plan = plan_conflict_resolution(self._RECORDS)
        keys = [(e.cve, e.field_name) for e in plan.entries]
        assert keys == sorted(keys)

    def test_the_serialised_plan_is_stable_json(self):
        first = json.dumps(plan_conflict_resolution(self._RECORDS).as_dict(),
                           sort_keys=True)
        second = json.dumps(plan_conflict_resolution(self._RECORDS).as_dict(),
                            sort_keys=True)
        assert first == second


class TestItReadsNothingOutsideItsArguments:
    """A planner that consults a clock or a store cannot be reviewed by diffing."""

    def test_the_module_imports_no_database_or_network(self):
        import pathlib

        import vuln_intel.conflict_planning as module

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        for banned in ("sqlite3", "psycopg", "sqlalchemy", "requests", "httpx",
                       "socket", "urllib"):
            assert banned not in source, f"conflict_planning.py references {banned}"

    def test_it_does_not_read_the_clock(self):
        import pathlib

        import vuln_intel.conflict_planning as module

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert "utcnow" not in source and "time.time" not in source
        assert "now()" not in source

    def test_it_writes_nothing(self):
        import inspect

        source = inspect.getsource(plan_conflict_resolution)
        for verb in ("write", "insert", "save", "persist", "commit"):
            assert verb not in source.lower()


class TestTheNextStepIsUseful:
    def test_missing_dissenters_blocks_on_provenance(self):
        plan = plan_conflict_resolution(
            [_record(items=[_conflict(dissenters=())])]
        )
        entry = plan.entries[0]
        assert entry.next_step == NextStep.GATHER_PROVENANCE
        assert "not known which source" in entry.rationale

    def test_a_timestamp_field_proposes_the_newer_value(self):
        plan = plan_conflict_resolution(
            [
                _record(
                    items=[
                        _conflict(
                            field="published",
                            kept="2021-12-10T10:00:00+00:00",
                            discarded=("2021-12-11T10:00:00+00:00",),
                        )
                    ]
                )
            ]
        )
        entry = plan.entries[0]
        assert entry.next_step == NextStep.CONFIRM_NEWER_TIMESTAMP
        assert entry.evidence["proposed_value"] == "2021-12-11T10:00:00+00:00"

    def test_an_unparseable_timestamp_proposes_nothing(self):
        """If a value is not a timestamp, "newer" is not a well-defined question."""
        plan = plan_conflict_resolution(
            [
                _record(
                    items=[
                        _conflict(field="published", kept="not a date",
                                  discarded=("2021-12-11T10:00:00+00:00",))
                    ]
                )
            ]
        )
        assert "proposed_value" not in plan.entries[0].evidence

    @pytest.mark.parametrize("field_name", TIMESTAMP_FIELDS)
    def test_every_timestamp_field_uses_the_timestamp_step(self, field_name):
        plan = plan_conflict_resolution(
            [_record(items=[_conflict(field=field_name)])]
        )
        assert plan.entries[0].next_step == NextStep.CONFIRM_NEWER_TIMESTAMP


class TestAggregates:
    def test_counts_by_field_and_step(self):
        plan = plan_conflict_resolution(
            [
                _record(cve="CVE-1", items=[_conflict(field="severity"),
                                            _conflict(field="severity")]),
                _record(cve="CVE-2", items=[_conflict(field="cvss",
                                                      dissenters=())]),
            ]
        )
        assert plan.by_field() == {"cvss": 1, "severity": 2}
        assert plan.by_next_step() == {
            NextStep.ANALYST_JUDGEMENT: 2,
            NextStep.GATHER_PROVENANCE: 1,
        }
        assert plan.requires_analyst == 2
        assert plan.blocked_on_provenance == 1

    def test_an_empty_input_gives_an_empty_plan_not_an_error(self):
        plan = plan_conflict_resolution([])
        assert plan.count == 0
        assert plan.as_dict()["entries"] == []

    def test_a_record_with_no_conflicts_is_ignored(self):
        plan = plan_conflict_resolution([{"cve": "CVE-1", "conflicts": []}])
        assert plan.count == 0


class TestItAcceptsRealRecords:
    """Not just dicts: the planner must work on the package's own dataclasses."""

    def test_it_plans_over_field_conflict_dataclasses(self):
        from vuln_intel.schema import FieldConflict

        class _Record:
            cve = "CVE-2021-44228"
            conflicts = (
                FieldConflict(
                    field="severity",
                    kept="critical",
                    discarded=("high",),
                    dissenters=("osv",),
                ),
            )

        plan = plan_conflict_resolution([_Record()])
        assert plan.count == 1
        assert plan.entries[0].field_name == "severity"
        assert plan.entries[0].dissenters == ("osv",)

    def test_dissenters_are_deduplicated_and_sorted(self):
        plan = plan_conflict_resolution(
            [_record(items=[_conflict(dissenters=("osv", "nvd", "osv"))])]
        )
        assert plan.entries[0].dissenters == ("nvd", "osv")
