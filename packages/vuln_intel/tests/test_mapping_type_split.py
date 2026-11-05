"""M3: the technique rollup exposes a per-mapping-type split (additive).

The default ``techniques`` list stays filtered to exploitation techniques; the
new ``techniques_by_mapping_type`` key shows every mapping type beside it, so a
consumer can see why a naive total differs from the filtered one (INTEGRATION_
READINESS.md §M3). Additive only: no existing key changed shape.
"""

from __future__ import annotations

from vuln_intel.threat_intel import (
    MAPPING_TYPES,
    AttackTechnique,
    TechniqueCorrelation,
    technique_rollup,
)


def _t(tid: str, mapping_type: str, name: str | None = None) -> AttackTechnique:
    return AttackTechnique(technique_id=tid, name=name or tid, mapping_type=mapping_type)


def _corr(cve: str, *techniques: AttackTechnique, consulted: bool = True) -> TechniqueCorrelation:
    return TechniqueCorrelation(
        cve=cve, techniques=techniques, consulted=consulted, source="ctid-test"
    )


class TestMappingTypeSplit:
    def test_default_list_still_counts_exploitation_only(self):
        rollup = technique_rollup(
            [
                _corr(
                    "CVE-2026-0001",
                    _t("T1190", "exploitation_technique"),
                    _t("T1005", "primary_impact"),
                )
            ]
        )
        as_dict = rollup.as_dict()
        assert [t["technique_id"] for t in as_dict["techniques"]] == ["T1190"]
        assert as_dict["techniques"][0]["cve_count"] == 1

    def test_split_lists_every_mapping_type_with_counts(self):
        rollup = technique_rollup(
            [
                _corr(
                    "CVE-2026-0001",
                    _t("T1190", "exploitation_technique"),
                    _t("T1005", "primary_impact"),
                    _t("T1486", "secondary_impact"),
                ),
                _corr(
                    "CVE-2026-0002",
                    _t("T1190", "exploitation_technique"),
                    _t("T1005", "primary_impact"),
                ),
            ]
        )
        split = rollup.as_dict()["techniques_by_mapping_type"]
        assert split["exploitation_technique"] == {"technique_count": 1, "cve_count": 2}
        assert split["primary_impact"] == {"technique_count": 1, "cve_count": 2}
        assert split["secondary_impact"] == {"technique_count": 1, "cve_count": 1}
        # a type nobody used is absent rather than zero-filled with a guess
        assert "uncategorized" not in split
        # every known mapping type is either present or genuinely unused
        assert set(split) <= set(MAPPING_TYPES)

    def test_unconsulted_rollup_has_empty_split_and_says_not_consulted(self):
        rollup = technique_rollup([_corr("CVE-2026-0001", consulted=False)])
        as_dict = rollup.as_dict()
        assert as_dict["consulted"] is False
        assert as_dict["techniques_by_mapping_type"] == {}

    def test_split_counts_distinct_cves_not_raw_mappings(self):
        # the same technique on the same CVE via two mapping types counts once
        # per type but the CVE once within that type
        rollup = technique_rollup(
            [
                _corr(
                    "CVE-2026-0001",
                    _t("T1190", "exploitation_technique"),
                    _t("T1190", "uncategorized"),
                )
            ]
        )
        split = rollup.as_dict()["techniques_by_mapping_type"]
        assert split["exploitation_technique"] == {"technique_count": 1, "cve_count": 1}
        assert split["uncategorized"] == {"technique_count": 1, "cve_count": 1}
