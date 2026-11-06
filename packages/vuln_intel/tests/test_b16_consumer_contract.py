"""B-16: compatibility tests pinning the PROPOSED consumer example semantics.

The doc `AGENT2_MAPPING_TYPE_CONSUMER_EXAMPLE.md` stays PROPOSED (not accepted);
these tests guarantee the *implementation* matches the documented shape, so any
future acceptance is a contract change, not a silent behaviour change.
"""

from __future__ import annotations

from vuln_intel.schema import CveId, NormalizedVulnerability, Origin
from vuln_intel.threat_intel import (
    AttackTechnique,
    CveTechniqueMap,
    correlate_techniques,
    technique_rollup,
)

_CVE1, _CVE2 = "CVE-2026-0001", "CVE-2026-0002"


def _map() -> CveTechniqueMap:
    return CveTechniqueMap(
        source="mitre-ctid/mappings-explorer", version="test",
        attack_version=None, created=None,
        by_cve={
            _CVE1: (
                AttackTechnique("T1190", "Exploit Public-Facing Application", "exploitation_technique"),
                AttackTechnique("T1005", "Data from Local System", "primary_impact"),
            ),
            _CVE2: (
                AttackTechnique("T1190", "Exploit Public-Facing Application", "exploitation_technique"),
                AttackTechnique("T1078", "Valid Accounts", "secondary_impact"),
            ),
        },
    )


def _records():
    return tuple(
        NormalizedVulnerability(cve=CveId.parse(c), origin=Origin.FIXTURE, sources=("osv",))
        for c in (_CVE1, _CVE2)
    )


class TestProposedContractShape:
    def test_documented_example_shape(self):
        roll = technique_rollup(correlate_techniques(_records(), _map()))
        d = roll.as_dict()
        # exactly the documented top-level keys
        assert set(d) == {
            "consulted", "total_cves", "techniques", "techniques_by_mapping_type",
            # M4: states that the key is the full technique id, never a prefix.
            "technique_key",
        }
        assert d["consulted"] is True and d["total_cves"] == 2
        # existing filtered list: exploitation techniques only, unchanged semantics
        assert d["techniques"] == [
            {"technique_id": "T1190", "name": "Exploit Public-Facing Application",
             "cve_count": 2, "cves": [_CVE1, _CVE2]}
        ]
        # additive split matches the documented example exactly
        assert d["techniques_by_mapping_type"] == {
            "exploitation_technique": {"technique_count": 1, "cve_count": 2},
            "primary_impact": {"technique_count": 1, "cve_count": 1},
            "secondary_impact": {"technique_count": 1, "cve_count": 1},
        }

    def test_not_consulted_is_explicit_not_empty(self):
        roll = technique_rollup(correlate_techniques(_records(), None))
        d = roll.as_dict()
        assert d["consulted"] is False
        assert d["techniques"] == [] and d["techniques_by_mapping_type"] == {}

    def test_uncategorized_key_only_when_present(self):
        m = CveTechniqueMap(
            source="s", version="v", attack_version=None, created=None,
            by_cve={_CVE1: (AttackTechnique("T9999", "Odd", "uncategorized"),)},
        )
        d = technique_rollup(correlate_techniques(_records()[:1], m)).as_dict()
        assert "uncategorized" in d["techniques_by_mapping_type"]
        d2 = technique_rollup(correlate_techniques(_records(), _map())).as_dict()
        assert "uncategorized" not in d2["techniques_by_mapping_type"]

    def test_sources_are_provenance_not_corroboration(self):
        rec = NormalizedVulnerability(
            cve=CveId.parse(_CVE1), origin=Origin.FIXTURE, sources=("nvd", "osv", "cisa-kev"),
        )
        d = rec.as_summary()
        assert d["sources"] == ["nvd", "osv", "cisa-kev"]  # provenance list, not a count field
        assert "corroboration_count" not in d


class TestM4TechniqueIdentity:
    """M4: the join key is the full technique id, including the sub-technique suffix.

    CTIS validates `attack_technique_ids` against `^T[0-9]{4}(\\.[0-9]{3})?$`, i.e. it
    accepts parent and sub-technique in one flat list. A downstream join keyed on the
    four-character prefix would fold `T1059.001` into `T1059` and inflate the parent,
    and neither side would be buggy. The contract has to say which one we mean.
    """

    @staticmethod
    def _rollup():
        from vuln_intel.threat_intel import AttackTechnique, CveTechniqueMap, correlate_techniques

        mapping = CveTechniqueMap(
            source="mitre-ctid/mappings-explorer",
            version="test",
            attack_version=None,
            created=None,
            by_cve={
                "CVE-2026-0001": (
                    AttackTechnique(
                        technique_id="T1059.001", name="PowerShell",
                        mapping_type="exploitation_technique",
                    ),
                ),
                "CVE-2026-0002": (
                    AttackTechnique(
                        technique_id="T1059.002", name="AppleScript",
                        mapping_type="exploitation_technique",
                    ),
                ),
                "CVE-2026-0003": (
                    AttackTechnique(
                        technique_id="T1059", name="Command Interpreter",
                        mapping_type="exploitation_technique",
                    ),
                ),
            },
        )
        from vuln_intel.schema import CveId, NormalizedVulnerability, Origin
        from vuln_intel.threat_intel import technique_rollup

        records = [
            NormalizedVulnerability(cve=CveId.parse(cve), origin=Origin.FIXTURE)
            for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")
        ]
        return technique_rollup(correlate_techniques(records, mapping))

    def test_sub_techniques_are_never_folded_into_the_parent_by_default(self):
        rollup = self._rollup()
        assert set(rollup.techniques) == {"T1059.001", "T1059.002", "T1059"}
        # If these folded, the parent count would be 3 rather than 1.
        assert len(rollup.by_technique["T1059"]) == 1
        assert len(rollup.by_technique["T1059.001"]) == 1

    def test_the_payload_states_which_key_it_used(self):
        """So a consumer cannot mistake the list for a prefix rollup."""
        payload = self._rollup().as_dict()
        assert payload["technique_key"] == "full_id"

    def test_parent_rollup_is_available_but_only_on_request(self):
        rollup = self._rollup()
        parents = rollup.parent_view()
        assert set(parents) == {"T1059"}
        # Three CVEs, deduplicated: T1059's own CVE counted once, not twice.
        assert len(parents["T1059"]) == 3

    def test_parent_rollup_does_not_double_count_a_cve(self):
        """The same bug one level up: a CVE touching parent and child at once."""
        from vuln_intel.threat_intel import (
            AttackTechnique,
            CveTechniqueMap,
            correlate_techniques,
            technique_rollup,
        )

        mapping = CveTechniqueMap(
            source="mitre-ctid/mappings-explorer", version="test", attack_version=None,
            created=None,
            by_cve={
                "CVE-2026-0009": (
                    AttackTechnique("T1059", "Command Interpreter", "exploitation_technique"),
                    AttackTechnique("T1059.001", "PowerShell", "exploitation_technique"),
                ),
            },
        )
        from vuln_intel.schema import CveId, NormalizedVulnerability, Origin

        record = NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-0009"), origin=Origin.FIXTURE
        )
        rollup = technique_rollup(correlate_techniques([record], mapping))
        parents = rollup.parent_view()
        assert parents["T1059"] == ("CVE-2026-0009",), "the same CVE was counted twice"

    def test_the_default_view_is_unchanged_by_this_addition(self):
        """M4 was an observation, not a contract change: no field was renamed."""
        payload = self._rollup().as_dict()
        assert "techniques" in payload and "techniques_by_mapping_type" in payload
        assert "techniques_by_parent" not in payload, (
            "parent rollup must stay opt-in, not appear in the payload unrequested"
        )
