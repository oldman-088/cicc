"""CVE → ATT&CK correlation.

The fixture is a real 10-object excerpt of MITRE CTID's KEV→ATT&CK mapping (see
``tests/fixtures/data/PROVENANCE.md``). Using the real table rather than an invented
one tests the parser against the shape the publisher actually emits — including
fields we ignore, which a hand-written fixture would never contain.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.schema import CveId, NormalizedVulnerability, Origin
from vuln_intel.threat_intel import (
    EXPLOITATION_TECHNIQUE,
    AttackTechnique,
    CveTechniqueMap,
    correlate_techniques,
    load_ctid_mapping,
    technique_rollup,
)

FIXTURE = Path(__file__).parent / "fixtures" / "data" / "ctid_kev_mapping_sample.json"


@pytest.fixture(scope="module")
def document() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def mapping(document):
    return load_ctid_mapping(document)


def record(cve: str) -> NormalizedVulnerability:
    return NormalizedVulnerability(cve=CveId.parse(cve), origin=Origin.FIXTURE)


class TestLoading:
    def test_reads_the_publishers_metadata(self, mapping) -> None:
        assert mapping.attack_version == "16.1"
        assert mapping.version == "07/28/2025"
        assert mapping.created is not None and mapping.created.year == 2025
        assert mapping.source.startswith("mitre-ctid")

    def test_groups_techniques_by_cve(self, mapping) -> None:
        assert mapping.mapped_cves == 3
        techniques = mapping.techniques_for("CVE-2019-13608")
        assert len(techniques) == 5

    def test_preserves_the_mapping_type(self, mapping) -> None:
        """Type is what distinguishes 'how it is exploited' from 'what it does'."""
        types = {t.mapping_type for t in mapping.techniques_for("CVE-2024-34102")}
        assert "exploitation_technique" in types
        assert "primary_impact" in types

    def test_preserves_the_curators_justification(self, mapping) -> None:
        """An assertion without its evidence cannot be reviewed or disputed."""
        technique = next(
            t
            for t in mapping.techniques_for("CVE-2024-34102")
            if t.technique_id == "T1190"
        )
        assert technique.comment
        assert len(technique.comment) > 20

    def test_lookup_is_case_insensitive_and_idempotent(self, mapping) -> None:
        assert mapping.techniques_for("cve-2024-34102") == mapping.techniques_for(
            CveId.parse("CVE-2024-34102")
        )

    def test_unknown_cve_yields_nothing(self, mapping) -> None:
        assert mapping.techniques_for("CVE-1999-0001") == ()

    def test_duplicate_rows_are_collapsed(self) -> None:
        one = {
            "capability_id": "CVE-2024-0001",
            "mapping_type": "exploitation_technique",
            "attack_object_id": "T1190",
            "attack_object_name": "Exploit Public-Facing Application",
        }
        loaded = load_ctid_mapping({"metadata": {}, "mapping_objects": [one, dict(one)]})
        assert len(loaded.techniques_for("CVE-2024-0001")) == 1

    def test_malformed_rows_are_skipped_not_fatal(self) -> None:
        """One bad row in a 1,000-row third-party dataset must not disable enrichment."""
        loaded = load_ctid_mapping(
            {
                "metadata": {},
                "mapping_objects": [
                    {"capability_id": "not-a-cve", "attack_object_id": "T1190"},
                    {"capability_id": "CVE-2024-0002"},
                    {
                        "capability_id": "CVE-2024-0003",
                        "attack_object_id": "T1190",
                        "attack_object_name": "Exploit Public-Facing Application",
                        "mapping_type": "exploitation_technique",
                    },
                ],
            }
        )
        assert loaded.mapped_cves == 1
        assert len(loaded.techniques_for("CVE-2024-0003")) == 1

    def test_unknown_mapping_type_becomes_uncategorized(self) -> None:
        loaded = load_ctid_mapping(
            {
                "metadata": {},
                "mapping_objects": [
                    {
                        "capability_id": "CVE-2024-0004",
                        "attack_object_id": "T1190",
                        "attack_object_name": "x",
                        "mapping_type": "something_new",
                    }
                ],
            }
        )
        (technique,) = loaded.techniques_for("CVE-2024-0004")
        assert technique.mapping_type == "uncategorized"

    @pytest.mark.parametrize("bad", [None, {}, {"mapping_objects": {}}, []])
    def test_a_broken_document_raises(self, bad) -> None:
        with pytest.raises(ValidationError):
            load_ctid_mapping(bad)


class TestTechniqueValidation:
    def test_empty_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AttackTechnique(technique_id="", name="x", mapping_type="primary_impact")

    def test_unknown_type_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AttackTechnique(technique_id="T1", name="x", mapping_type="made_up")


class TestCorrelation:
    def test_mapped_cve_reports_its_techniques(self, mapping) -> None:
        (correlation,) = correlate_techniques([record("CVE-2024-34102")], mapping)
        assert correlation.consulted is True
        assert correlation.mapped is True
        assert correlation.source is not None

    def test_unmapped_cve_is_distinguishable_from_unconsulted(self, mapping) -> None:
        """The single most important property of this module."""
        mapped, unmapped = correlate_techniques(
            [record("CVE-2024-34102"), record("CVE-1999-0001")], mapping
        )
        none_at_all = correlate_techniques([record("CVE-2024-34102")], None)[0]

        assert unmapped.consulted is True and unmapped.mapped is False
        assert none_at_all.consulted is False and none_at_all.mapped is False
        assert mapped.mapped is True

    def test_unconsulted_reachability_is_unknown_not_false(self, mapping) -> None:
        unmapped = correlate_techniques([record("CVE-1999-0001")], mapping)[0]
        unconsulted = correlate_techniques([record("CVE-1999-0001")], None)[0]
        assert unmapped.externally_reachable is None
        assert unconsulted.externally_reachable is None

    def test_public_facing_exploitation_is_flagged(self, mapping) -> None:
        (correlation,) = correlate_techniques([record("CVE-2024-34102")], mapping)
        assert correlation.externally_reachable is True

    def test_impact_only_mapping_does_not_claim_reachability(self) -> None:
        """T1059 as a *consequence* is not evidence the flaw is internet-facing."""
        mapping = load_ctid_mapping(
            {
                "metadata": {},
                "mapping_objects": [
                    {
                        "capability_id": "CVE-2024-0005",
                        "attack_object_id": "T1059",
                        "attack_object_name": "Command and Scripting Interpreter",
                        "mapping_type": "primary_impact",
                    }
                ],
            }
        )
        (correlation,) = correlate_techniques([record("CVE-2024-0005")], mapping)
        assert correlation.mapped is True
        assert correlation.externally_reachable is False

    def test_results_are_ordered_like_the_input(self, mapping) -> None:
        records = [record("CVE-2024-4671"), record("CVE-2024-34102")]
        correlations = correlate_techniques(records, mapping)
        assert [c.cve for c in correlations] == ["CVE-2024-4671", "CVE-2024-34102"]

    def test_as_dict_is_json_serialisable(self, mapping) -> None:
        correlations = correlate_techniques([record("CVE-2024-34102")], mapping)
        payload = [c.as_dict() for c in correlations]
        assert json.loads(json.dumps(payload))[0]["cve"] == "CVE-2024-34102"


class TestRollup:
    def test_counts_cves_per_technique(self, mapping) -> None:
        records = [record(c) for c in ("CVE-2019-13608", "CVE-2024-34102", "CVE-2024-4671")]
        rollup = technique_rollup(correlate_techniques(records, mapping))
        assert rollup.consulted is True
        assert rollup.total_cves == 3
        # In this excerpt only CVE-2024-34102 carries T1190 as an exploitation
        # technique; CVE-2024-4671 uses T1189 (Drive-by Compromise) instead.
        assert "T1190" in rollup.by_technique
        assert rollup.by_technique["T1190"] == ("CVE-2024-34102",)

    def test_rollup_excludes_impact_techniques(self, mapping) -> None:
        """A consequence must not be able to outrank the exposure that enabled it."""
        records = [record("CVE-2024-34102")]
        correlations = correlate_techniques(records, mapping)
        rollup = technique_rollup(correlations)
        impact_only = {
            t.technique_id
            for t in correlations[0].techniques
            if t.mapping_type != EXPLOITATION_TECHNIQUE
        }
        assert impact_only
        assert not (impact_only & set(rollup.by_technique))

    def test_rollup_is_ordered_by_cve_count_descending(self, mapping) -> None:
        records = [record(c) for c in ("CVE-2019-13608", "CVE-2024-34102", "CVE-2024-4671")]
        rollup = technique_rollup(correlate_techniques(records, mapping))
        counts = [len(v) for v in rollup.by_technique.values()]
        assert counts == sorted(counts, reverse=True)

    def test_unconsulted_rollup_says_so(self) -> None:
        rollup = technique_rollup(correlate_techniques([record("CVE-2024-34102")], None))
        assert rollup.consulted is False
        assert rollup.techniques == ()

    def test_rollup_serialises_for_the_threat_intel_consumer(self, mapping) -> None:
        rollup = technique_rollup(
            correlate_techniques([record("CVE-2024-34102")], mapping)
        )
        payload = json.loads(json.dumps(rollup.as_dict()))
        assert payload["techniques"][0]["technique_id"].startswith("T")
        assert payload["techniques"][0]["name"] != "unknown"


class TestMapIsImmutable:
    def test_requires_a_source(self) -> None:
        with pytest.raises(ValidationError):
            CveTechniqueMap(source="", version="1", attack_version=None, created=None)

    def test_cannot_be_mutated_after_a_report_quoted_it(self, mapping) -> None:
        """A frozen dataclass alone does not achieve this; the mapping must be frozen too."""
        with pytest.raises(TypeError):
            mapping.by_cve["CVE-2024-34102"] = ()  # type: ignore[index]
