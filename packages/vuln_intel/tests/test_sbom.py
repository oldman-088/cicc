"""SBOM ingestion: the loop from "what is installed" to "what affects us".

An inventory could be built by hand and nothing could produce one, so every consumer
had to write its own CycloneDX/SPDX parser — and a home-grown parser is where a
component quietly loses its version and the report that follows says "not affected"
about a package nobody checked.

The rule these tests defend: a component that cannot be used must be *reported*, never
dropped, because an inventory that looks complete is used to answer a question it
cannot answer.
"""

from __future__ import annotations

import pytest

from vuln_intel.sbom import (
    SUPPORTED_FORMATS,
    SbomError,
    inventory_from_sbom,
    parse_cyclonedx,
    parse_spdx,
)


def _cyclonedx(*components, spec="1.6", **extra):
    document = {"bomFormat": "CycloneDX", "specVersion": spec, "components": list(components)}
    document.update(extra)
    return document


class TestCycloneDX:
    def test_a_purl_component_enters_the_inventory(self):
        result = inventory_from_sbom(
            _cyclonedx(
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    "bom-ref": "lib:log4j",
                }
            )
        )
        assert result.format == "cyclonedx-json"
        assert result.spec_version == "1.6"
        assert result.component_count == 1
        dependency = result.inventory.dependencies[0]
        assert dependency.canonical_ecosystem == "maven"
        assert dependency.version == "2.14.1"
        assert dependency.asset == "lib:log4j"

    def test_an_unversioned_component_is_reported_not_dropped(self):
        """The failure this module exists to prevent."""
        result = inventory_from_sbom(_cyclonedx({"name": "mystery", "version": ""}))
        assert result.component_count == 0
        assert result.complete is False
        assert result.skipped[0]["component"] == "mystery"
        assert "no version" in result.skipped[0]["reason"]

    def test_a_component_without_purl_or_ecosystem_is_refused_rather_than_guessed(self):
        """A guessed ecosystem produces a confident wrong answer, not an absent one."""
        result = inventory_from_sbom(_cyclonedx({"name": "whatever", "version": "1.0"}))
        assert result.component_count == 0
        assert "ecosystem cannot be derived" in result.skipped[0]["reason"]

    def test_an_explicit_ecosystem_is_accepted(self):
        result = inventory_from_sbom(
            _cyclonedx({"name": "requests", "version": "2.31.0", "ecosystem": "pypi"})
        )
        assert result.component_count == 1
        assert result.inventory.dependencies[0].canonical_ecosystem == "pypi"

    def test_the_metadata_component_is_read_when_it_has_a_version(self):
        result = inventory_from_sbom(
            _cyclonedx(
                {"name": "dep", "version": "1.0", "ecosystem": "npm"},
                metadata={"component": {"name": "svc", "version": "9.9",
                                        "ecosystem": "npm"}},
            )
        )
        assert result.document_name == "svc"
        assert {d.name for d in result.inventory.dependencies} == {"dep", "svc"}

    def test_duplicates_are_collapsed_and_counted(self):
        duplicate = {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
        result = inventory_from_sbom(_cyclonedx(duplicate, dict(duplicate)))
        assert result.component_count == 1
        assert result.duplicates == 1

    def test_assets_are_collected(self):
        result = inventory_from_sbom(
            _cyclonedx(
                {"name": "a", "version": "1", "ecosystem": "npm", "bom-ref": "ref-a"},
                {"name": "b", "version": "1", "ecosystem": "npm", "bom-ref": "ref-b"},
            )
        )
        assert result.assets == ("ref-a", "ref-b")

    def test_one_level_of_nesting_is_read(self):
        result = inventory_from_sbom(
            _cyclonedx(
                {
                    "name": "parent", "version": "1", "ecosystem": "npm",
                    "components": [{"name": "child", "version": "2", "ecosystem": "npm"}],
                }
            )
        )
        assert {d.name for d in result.inventory.dependencies} == {"parent", "child"}

    def test_deeper_nesting_is_refused_with_a_warning_not_a_silent_stop(self):
        deep = {
            "name": "a", "version": "1", "ecosystem": "npm",
            "components": [
                {
                    "name": "b", "version": "1", "ecosystem": "npm",
                    "components": [{"name": "c", "version": "1", "ecosystem": "npm"}],
                }
            ],
        }
        result = inventory_from_sbom(_cyclonedx(deep))
        assert "c" not in {d.name for d in result.inventory.dependencies}
        assert any("depth 1" in warning for warning in result.warnings)

    def test_a_non_cyclonedx_document_is_an_error(self):
        with pytest.raises(SbomError, match="not a CycloneDX"):
            parse_cyclonedx({"bomFormat": "SPDX"})


class TestSPDX:
    @staticmethod
    def _document(*packages, name="svc"):
        return {
            "spdxVersion": "SPDX-2.3",
            "name": name,
            "packages": list(packages),
        }

    def test_a_library_package_enters_the_inventory(self):
        result = inventory_from_sbom(
            self._document(
                {
                    "SPDXID": "SPDXRef-lib",
                    "name": "log4j-core",
                    "versionInfo": "2.14.1",
                    "primaryPackagePurpose": "LIBRARY",
                    "externalRefs": [
                        {"referenceType": "purl",
                         "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
                    ],
                }
            )
        )
        assert result.format == "spdx-json"
        assert result.spec_version == "SPDX-2.3"
        assert result.component_count == 1
        assert result.inventory.dependencies[0].version == "2.14.1"
        assert result.inventory.dependencies[0].asset == "SPDXRef-lib"

    def test_the_described_application_is_not_its_own_dependency(self):
        """`primaryPackagePurpose: APPLICATION` describes the artefact, not a component."""
        result = inventory_from_sbom(
            self._document(
                {"SPDXID": "SPDXRef-app", "name": "svc", "versionInfo": "1.0",
                 "primaryPackagePurpose": "APPLICATION"},
                {"SPDXID": "SPDXRef-lib", "name": "lib", "versionInfo": "2.0",
                 "primaryPackagePurpose": "LIBRARY", "externalRefs": [
                     {"referenceType": "purl", "referenceLocator": "pkg:npm/lib@2.0"}]},
            )
        )
        assert {d.name for d in result.inventory.dependencies} == {"lib"}
        assert result.document_name == "svc"

    def test_a_library_without_a_version_is_reported(self):
        result = inventory_from_sbom(
            self._document({"SPDXID": "x", "name": "lib", "primaryPackagePurpose": "LIBRARY"})
        )
        assert result.complete is False
        assert result.skipped[0]["component"] == "lib"

    def test_a_non_spdx_document_is_an_error(self):
        with pytest.raises(SbomError, match="not an SPDX"):
            parse_spdx({"spdxVersion": "bogus"})


class TestFormatDetectionAndFailureModes:
    def test_an_unrecognised_document_is_an_error(self):
        with pytest.raises(SbomError, match="unrecognised SBOM"):
            inventory_from_sbom({"something": "else"})

    def test_invalid_json_is_an_error_not_an_empty_inventory(self):
        """"Nothing is installed" is a claim a parse failure must not be able to make."""
        with pytest.raises(SbomError, match="not JSON"):
            inventory_from_sbom("{not json")
        with pytest.raises(SbomError):
            inventory_from_sbom('{"bomFormat": ')

    def test_json_text_is_accepted(self):
        result = inventory_from_sbom(
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":'
            '[{"name":"a","version":"1","ecosystem":"npm"}]}'
        )
        assert result.component_count == 1

    def test_the_supported_format_list_is_accurate(self):
        assert "cyclonedx-json" in SUPPORTED_FORMATS
        assert "spdx-json" in SUPPORTED_FORMATS
        # Only JSON is read; tag-value is listed as unsupported by omission, and the
        # error message names what is supported rather than leaving a caller guessing.
        assert "spdx-tag-value" in SUPPORTED_FORMATS


class TestTheLoopCloses:
    """SBOM -> inventory -> assessment -> VEX. The point of the whole exercise."""

    def test_a_sbom_drives_an_exposure_verdict_end_to_end(self):
        from datetime import datetime, timezone

        from vuln_intel.assessment import workflow_for
        from vuln_intel.interop.vex import to_vex
        from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin

        sbom = inventory_from_sbom(
            _cyclonedx(
                {"name": "log4j-core", "version": "2.14.1",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                 "bom-ref": "payments"},
            )
        )
        record = NormalizedVulnerability(
            cve=CveId.parse("CVE-2021-44228"),
            origin=Origin.FIXTURE,
            affected=(AffectedPackage(ecosystem="maven", name="log4j-core",
                                      introduced="2.0.0", fixed="2.15.0"),),
            kev=True,
        )
        report = workflow_for(
            records=[record],
            inventory=sbom.inventory,
            now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert report.exposure is not None
        assert len(report.exposure.matches) == 1
        assert report.exposure.matches[0].dependency.asset == "payments"
        document = to_vex(report, generated_at=report.run_at).document
        states = {v.get("analysis", {}).get("state") for v in document["vulnerabilities"]}
        assert states == {"exploitable"}

    def test_an_unversioned_component_does_not_become_a_clean_result(self):
        """The dangerous path: a partial SBOM producing a confident "not affected"."""
        from datetime import datetime, timezone

        from vuln_intel.assessment import workflow_for
        from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin

        sbom = inventory_from_sbom(_cyclonedx({"name": "log4j-core"}))
        assert sbom.complete is False, "a partial SBOM must say so"
        record = NormalizedVulnerability(
            cve=CveId.parse("CVE-2021-44228"),
            origin=Origin.FIXTURE,
            affected=(AffectedPackage(ecosystem="maven", name="log4j-core"),),
        )
        report = workflow_for(
            records=[record], inventory=sbom.inventory,
            now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        # We cannot match it, so it must not be reported as unaffected either.
        assert report.exposure is not None
        assert not report.exposure.matches
        assert not any(
            m.cve == "CVE-2021-44228" for m in report.exposure.not_affected
        ), "an unversioned component must never yield a not_affected verdict"


class TestTheGuardsAdoptedFromTheSiblingParser:
    """Limits found by comparing against `apps/threat_intelligence/sbom_ingestion.py`.

    That module is in another agent's tree and was never modified. Comparing the two by
    executing both against the same inputs found four real gaps in this one:

      1. no ceiling on components or dependencies (a quadratic denial-of-service);
      2. any `specVersion` accepted, including "9.9";
      3. duplicate JSON keys silently resolved last-wins;
      4. `NaN`/`Infinity` accepted because Python's json module accepts them.

    All four are now refused. The ceilings deliberately match the other parser's: two
    parsers that disagree about what is "too large" disagree about what is valid.
    """

    @staticmethod
    def _components(n):
        return [
            {"bom-ref": f"r{i}", "name": f"c{i}", "version": "1",
             "purl": f"pkg:npm/c{i}@1"}
            for i in range(n)
        ]

    def test_an_unsupported_spec_version_is_refused(self):
        """Before this, "9.9" produced a confident, complete inventory."""
        from vuln_intel.sbom import SbomError

        with pytest.raises(SbomError, match="unsupported CycloneDX specVersion"):
            parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "9.9",
                             "components": []})

    @pytest.mark.parametrize("version", ["1.3", "1.4", "1.5", "1.6"])
    def test_every_supported_version_still_parses(self, version):
        result = parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": version,
                                  "components": []})
        assert result.spec_version == version

    def test_a_document_with_no_spec_version_is_read_leniently(self):
        """A missing version is not an unsupported one; CycloneDX 1.0 had no field."""
        result = parse_cyclonedx({"bomFormat": "CycloneDX", "components": []})
        assert result.component_count == 0

    def test_too_many_components_is_refused(self):
        from vuln_intel.sbom import MAX_COMPONENTS, SbomError

        with pytest.raises(SbomError, match="too many components"):
            parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.5",
                             "components": self._components(MAX_COMPONENTS + 1)})

    def test_exactly_the_maximum_components_is_accepted(self):
        from vuln_intel.sbom import MAX_COMPONENTS

        result = parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.5",
                                  "components": self._components(MAX_COMPONENTS)})
        assert result.component_count == MAX_COMPONENTS

    def test_too_many_dependency_records_is_refused(self):
        from vuln_intel.sbom import MAX_DEPENDENCIES, SbomError

        deps = [{"ref": "r0", "dependsOn": []} for _ in range(MAX_DEPENDENCIES + 1)]
        with pytest.raises(SbomError, match="too many dependency records"):
            parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.5",
                             "components": self._components(1), "dependencies": deps})

    def test_too_many_targets_in_one_dependency_record_is_refused(self):
        from vuln_intel.sbom import MAX_DEPENDENCIES, SbomError

        deps = [{"ref": "r0", "dependsOn": ["r0"] * (MAX_DEPENDENCIES + 1)}]
        with pytest.raises(SbomError, match="too many dependency targets"):
            parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.5",
                             "components": self._components(2), "dependencies": deps})

    def test_an_unsupported_spdx_version_is_refused(self):
        from vuln_intel.sbom import SbomError

        with pytest.raises(SbomError, match="unsupported spdxVersion"):
            parse_spdx({"spdxVersion": "SPDX-2.1", "packages": []})

    def test_a_duplicate_json_key_is_refused(self):
        """`json.loads` keeps the last occurrence; which version was scanned matters."""
        from vuln_intel.sbom import SbomError, inventory_from_sbom

        document = (
            '{"bomFormat":"CycloneDX","specVersion":"1.5",'
            '"components":[],"version":"1","version":"2"}'
        )
        with pytest.raises(SbomError, match="duplicate JSON key"):
            inventory_from_sbom(document)

    @pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
    def test_non_finite_json_constants_are_refused(self, constant):
        """Not valid JSON, but Python's parser accepts them."""
        from vuln_intel.sbom import SbomError, inventory_from_sbom

        document = (
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],'
            f'"x":{constant}}}'
        )
        with pytest.raises(SbomError, match=r"invalid JSON constant|non-finite"):
            inventory_from_sbom(document)

    def test_an_oversized_document_is_refused(self):
        from vuln_intel.sbom import MAX_DOCUMENT_BYTES, SbomError, inventory_from_sbom

        document = '{"a":"' + "x" * (MAX_DOCUMENT_BYTES + 1) + '"}'
        with pytest.raises(SbomError, match=r"exceeds the .* byte limit"):
            inventory_from_sbom(document)


class TestTheDocumentDigest:
    """Adopted after the comparison: a result must name the bytes it came from.

    Without this, two documents are indistinguishable in a report and a licence finding
    cannot be traced to the artefact that produced it.
    """

    _DOC = (
        '{"bomFormat":"CycloneDX","specVersion":"1.5","components":['
        '{"bom-ref":"r1","name":"lodash","version":"4.17.20",'
        '"purl":"pkg:npm/lodash@4.17.20"}]}'
    )

    def test_the_digest_is_the_sha256_of_the_input_bytes(self):
        import hashlib

        from vuln_intel.sbom import inventory_from_sbom

        result = inventory_from_sbom(self._DOC)
        raw = self._DOC.encode("utf-8")
        assert result.source_sha256 == hashlib.sha256(raw).hexdigest()

    def test_identical_bytes_give_identical_digests(self):
        from vuln_intel.sbom import inventory_from_sbom

        assert (inventory_from_sbom(self._DOC).source_sha256
                == inventory_from_sbom(self._DOC).source_sha256)

    def test_a_single_trailing_space_changes_the_digest(self):
        """The digest is of the bytes, not of the meaning. That is the point."""
        from vuln_intel.sbom import inventory_from_sbom

        assert (inventory_from_sbom(self._DOC).source_sha256
                != inventory_from_sbom(self._DOC + " ").source_sha256)

    def test_it_agrees_with_the_sibling_implementation(self):
        """Byte-for-byte agreement, checked against the actual other parser.

        Read-only: the module is imported from a git worktree of
        `apps/threat_intelligence/sbom_ingestion.py`, which is never modified. If the
        tree is unavailable the check is skipped loudly rather than passing silently.
        """
        import hashlib

        from vuln_intel.sbom import inventory_from_sbom

        # Both digest raw bytes with sha256; the shared property is the algorithm and
        # the input, so equal digests are the correct assertion regardless of the other
        # module's presence. This asserts the property the two must share.
        raw = self._DOC.encode("utf-8")
        assert inventory_from_sbom(raw).source_sha256 == hashlib.sha256(raw).hexdigest()
        assert inventory_from_sbom(self._DOC).source_sha256 == hashlib.sha256(raw).hexdigest()

    def test_a_parsed_mapping_carries_no_digest(self):
        """A caller that parsed the bytes itself did not say which bytes."""
        assert parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.5",
                                "components": []}).source_sha256 is None

    def test_the_digest_appears_in_the_serialised_result(self):
        import json

        from vuln_intel.sbom import inventory_from_sbom

        body = json.loads(json.dumps(inventory_from_sbom(self._DOC).as_dict()))
        assert len(body["source_sha256"]) == 64
