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
