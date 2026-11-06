"""§5.6 breadth: licence information and dependency relationships.

The Master Prompt asks for six things under SBOM Intelligence. Ingestion and
component identification were covered; licences and dependency relationships were
not, and "dependency relationship visualisation" cannot be built on a flat list.

The rules these tests defend:

* The artefact being described is **not** a dependency of itself. Counting it as one
  both pollutes the inventory and — because an application usually has no purl —
  made a perfectly well-formed BOM report ``complete=False``.
* A licence that the document does not state is **absent**, not empty and not
  ``NOASSERTION``. "We don't know the licence" and "there is no licence" are
  different findings.
* A relationship that points at something the document never described is
  **reported**, not invented and not silently dropped.
* Only edges that mean "depends on" become edges. SPDX ``CONTAINS``/``DESCRIBES``
  describe structure, not dependency, and conflating them is how a library ends up
  listed as depending on the application that uses it.
"""

from __future__ import annotations

from vuln_intel.sbom import inventory_from_sbom


def _cdx(**extra):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    doc.update(extra)
    return doc


def _spdx(**extra):
    doc = {"spdxVersion": "SPDX-2.3", "name": "test-sbom"}
    doc.update(extra)
    return doc


class TestLicensesCycloneDx:
    def test_a_declared_licence_id_is_recorded(self):
        result = inventory_from_sbom(
            _cdx(components=[
                {"name": "lodash", "version": "4.17.20", "bom-ref": "c1",
                 "purl": "pkg:npm/lodash@4.17.20",
                 "licenses": [{"license": {"id": "MIT"}}]},
            ])
        )
        assert result.licenses["lodash"] == ("MIT",)

    def test_a_named_licence_is_used_when_no_id_is_given(self):
        """CycloneDX allows a free-text name; dropping it loses real information."""
        result = inventory_from_sbom(
            _cdx(components=[
                {"name": "lodash", "version": "4.17.20", "bom-ref": "c1",
                 "purl": "pkg:npm/lodash@4.17.20",
                 "licenses": [{"license": {"name": "Apache License 2.0"}}]},
            ])
        )
        assert result.licenses["lodash"] == ("Apache License 2.0",)

    def test_a_licence_expression_is_recorded_verbatim(self):
        result = inventory_from_sbom(
            _cdx(components=[
                {"name": "x", "version": "1", "bom-ref": "c1",
                 "purl": "pkg:npm/x@1.0.0",
                 "licenses": [{"expression": "MIT OR Apache-2.0"}]},
            ])
        )
        assert result.licenses["x"] == ("MIT OR Apache-2.0",)

    def test_a_component_with_no_licences_is_absent_not_empty(self):
        """"Not stated" must not look like "none"."""
        result = inventory_from_sbom(
            _cdx(components=[
                {"name": "x", "version": "1", "bom-ref": "c1", "purl": "pkg:npm/x@1.0.0"},
            ])
        )
        assert "x" not in result.licenses

    def test_licences_are_keyed_by_the_name_the_inventory_uses(self):
        result = inventory_from_sbom(
            _cdx(components=[
                {"name": "log4j-core", "version": "2.14.1", "bom-ref": "c1",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                 "licenses": [{"license": {"id": "Apache-2.0"}}]},
            ])
        )
        # Same key as the inventory, with the Maven group qualified as advisories do.
        assert result.licenses["org.apache.logging.log4j:log4j-core"] == ("Apache-2.0",)


class TestLicensesSpdx:
    def test_declared_and_concluded_are_both_kept_declared_first(self):
        result = inventory_from_sbom(
            _spdx(packages=[
                {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.20",
                 "licenseDeclared": "MIT", "licenseConcluded": "Apache-2.0",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
            ])
        )
        # A disagreement between the two is exactly what a reviewer needs to see.
        assert result.licenses["lodash"] == ("MIT", "Apache-2.0")

    def test_noassertion_is_not_reported_as_a_licence(self):
        result = inventory_from_sbom(
            _spdx(packages=[
                {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.20",
                 "licenseDeclared": "NOASSERTION", "licenseConcluded": "NONE",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
            ])
        )
        assert "lodash" not in result.licenses

    def test_a_real_licence_survives_a_noassertion_neighbour(self):
        result = inventory_from_sbom(
            _spdx(packages=[
                {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.20",
                 "licenseDeclared": "MIT", "licenseConcluded": "NOASSERTION",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
            ])
        )
        assert result.licenses["lodash"] == ("MIT",)


class TestTheDescribedArtefactIsNotItsOwnDependency:
    def test_an_application_without_a_purl_does_not_make_the_bom_partial(self):
        """The defect this class was written for: every real application BOM
        reported complete=False because the app itself was listed as skipped."""
        result = inventory_from_sbom(
            _cdx(
                metadata={"component": {"name": "payments", "version": "1.0",
                                        "bom-ref": "app"}},
                components=[{"name": "lodash", "version": "4.17.20", "bom-ref": "c1",
                             "purl": "pkg:npm/lodash@4.17.20"}],
            )
        )
        assert result.complete is True
        assert result.skipped == ()
        assert result.document_name == "payments"

    def test_a_genuinely_unusable_component_still_breaks_completeness(self):
        result = inventory_from_sbom(
            _cdx(
                metadata={"component": {"name": "payments", "version": "1.0",
                                        "bom-ref": "app"}},
                components=[
                    {"name": "lodash", "version": "4.17.20", "bom-ref": "c1",
                     "purl": "pkg:npm/lodash@4.17.20"},
                    {"name": "mystery", "bom-ref": "c2"},
                ],
            )
        )
        assert result.complete is False
        assert [s["component"] for s in result.skipped] == ["mystery"]

    def test_an_spdx_application_package_is_not_a_component(self):
        result = inventory_from_sbom(
            _spdx(packages=[
                {"SPDXID": "SPDXRef-App", "name": "payments", "versionInfo": "1.0",
                 "primaryPackagePurpose": "APPLICATION"},
                {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.20",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
            ])
        )
        assert result.component_count == 1
        assert result.complete is True


class TestRelationshipGraphCycloneDx:
    def _doc(self, depends_on, extra_components=()):
        return _cdx(
            metadata={"component": {"name": "payments", "version": "1.0",
                                    "bom-ref": "app"}},
            components=[
                {"name": "lodash", "version": "4.17.20", "bom-ref": "c1",
                 "purl": "pkg:npm/lodash@4.17.20"},
                {"name": "left-pad", "version": "1.3.0", "bom-ref": "c2",
                 "purl": "pkg:npm/left-pad@1.3.0"},
                *extra_components,
            ],
            dependencies=depends_on,
        )

    def test_a_direct_dependency_edge_is_recorded(self):
        result = inventory_from_sbom(self._doc([{"ref": "app", "dependsOn": ["c1"]}]))
        assert result.relationships == (("payments", "lodash"),)

    def test_a_transitive_edge_is_recorded(self):
        result = inventory_from_sbom(
            self._doc([
                {"ref": "app", "dependsOn": ["c1"]},
                {"ref": "c1", "dependsOn": ["c2"]},
            ])
        )
        assert ("lodash", "left-pad") in result.relationships

    def test_a_reference_to_an_unknown_component_is_reported(self):
        """Inventing the edge would be worse than reporting it."""
        result = inventory_from_sbom(
            self._doc([{"ref": "app", "dependsOn": ["c1", "ghost"]}])
        )
        assert result.relationships == (("payments", "lodash"),)
        assert any("ghost" in w for w in result.warnings)

    def test_a_missing_dependencies_array_is_not_an_error(self):
        result = inventory_from_sbom(self._doc([]))
        assert result.relationships == ()
        assert result.warnings == ()

    def test_edges_are_deduplicated(self):
        result = inventory_from_sbom(
            self._doc([
                {"ref": "app", "dependsOn": ["c1"]},
                {"ref": "app", "dependsOn": ["c1"]},
            ])
        )
        assert result.relationships == (("payments", "lodash"),)


class TestRelationshipGraphSpdx:
    def _doc(self, relationships):
        return _spdx(
            packages=[
                {"SPDXID": "SPDXRef-App", "name": "payments", "versionInfo": "1.0",
                 "primaryPackagePurpose": "APPLICATION"},
                {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.20",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
                {"SPDXID": "SPDXRef-b", "name": "left-pad", "versionInfo": "1.3.0",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:npm/left-pad@1.3.0"}]},
            ],
            relationships=relationships,
        )

    def test_depends_on_is_an_edge(self):
        result = inventory_from_sbom(
            self._doc([{"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": "SPDXRef-a"}])
        )
        assert result.relationships == (("payments", "lodash"),)

    def test_dependency_of_is_the_same_edge_in_the_other_direction(self):
        """SPDX states both; treating them differently loses half the graph."""
        result = inventory_from_sbom(
            self._doc([{"spdxElementId": "SPDXRef-a", "relationshipType": "DEPENDENCY_OF",
                        "relatedSpdxElement": "SPDXRef-App"}])
        )
        assert result.relationships == (("payments", "lodash"),)

    def test_contains_is_not_a_dependency_edge(self):
        result = inventory_from_sbom(
            self._doc([{"spdxElementId": "SPDXRef-App", "relationshipType": "CONTAINS",
                        "relatedSpdxElement": "SPDXRef-a"}])
        )
        assert result.relationships == ()

    def test_describes_is_not_a_dependency_edge(self):
        result = inventory_from_sbom(
            self._doc([{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-App"}])
        )
        assert result.relationships == ()

    def test_an_unresolvable_relationship_is_reported(self):
        result = inventory_from_sbom(
            self._doc([{"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": "SPDXRef-missing"}])
        )
        assert result.relationships == ()
        assert any("missing" in w for w in result.warnings)


class TestTheGraphIsUsableForTriage:
    def test_a_direct_dependency_can_be_distinguished_from_a_transitive_one(self):
        """The question a finding actually raises: do we depend on this directly?"""
        result = inventory_from_sbom(
            _cdx(
                metadata={"component": {"name": "payments", "version": "1.0",
                                        "bom-ref": "app"}},
                components=[
                    {"name": "lodash", "version": "4.17.20", "bom-ref": "c1",
                     "purl": "pkg:npm/lodash@4.17.20"},
                    {"name": "left-pad", "version": "1.3.0", "bom-ref": "c2",
                     "purl": "pkg:npm/left-pad@1.3.0"},
                ],
                dependencies=[
                    {"ref": "app", "dependsOn": ["c1"]},
                    {"ref": "c1", "dependsOn": ["c2"]},
                ],
            )
        )
        direct = {child for parent, child in result.relationships if parent == "payments"}
        assert direct == {"lodash"}
        assert "left-pad" not in direct
