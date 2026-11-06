"""A differential harness that proves whether one canonical parser could serve both.

The brief asks whether the two SBOM parsers can share a canonical implementation
"without losing existing coverage". That question has a precise form: for every input
where the two *currently* disagree, is the disagreement a **coverage** difference (one
parser sees something the other cannot) or a **policy** difference (both see it and choose
differently)?

- Coverage differences mean a canonical parser must keep both capabilities.
- Policy differences mean a canonical parser must pick one behaviour, which is an owner
  decision, not a refactor.

This harness answers that with data. It feeds identical byte strings to both parsers and
records the outcome per input, so the consolidation recommendation rests on executed
evidence rather than on reading two files.

**Read-only with respect to the other implementation.** Agent 3's module is extracted to a
temporary directory with `git archive`; their branch is never checked out and their files
are never edited. If the extraction fails, every test here **skips with the missing
prerequisite named** rather than passing silently.

Run directly for the full matrix:

    python -m pytest tests/test_parser_consolidation.py -v
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

import pytest

OTHER_BRANCH = "origin/arena/93315d2c-cicc"
OTHER_MODULE = "apps/threat_intelligence"


def _repo_root() -> pathlib.Path:
    for candidate in pathlib.Path(__file__).resolve().parents:
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("no .git directory above this test file")


def _extract_other() -> pathlib.Path | None:
    git = shutil.which("git")
    tar = shutil.which("tar")
    if git is None or tar is None:
        return None
    check = subprocess.run(  # noqa: S603 - absolute path, fixed argv
        [git, "rev-parse", "--verify", OTHER_BRANCH],
        cwd=str(_repo_root()), capture_output=True, text=True, check=False,
    )
    if check.returncode != 0:
        return None
    # A unique directory per run. A fixed path would let two concurrent test runs
    # extract into the same tree and delete each other's files mid-run.
    target = pathlib.Path(tempfile.mkdtemp(prefix="cicc-parser-compare-"))
    archive = subprocess.run(  # noqa: S603 - absolute path, fixed argv
        [git, "archive", OTHER_BRANCH, OTHER_MODULE],
        cwd=str(_repo_root()), capture_output=True, check=False,
    )
    if archive.returncode != 0 or not archive.stdout:
        return None
    untar = subprocess.run(  # noqa: S603 - absolute path, fixed argv
        [tar, "-x", "-C", str(target)], input=archive.stdout, capture_output=True,
        check=False,
    )
    if untar.returncode != 0:
        return None
    return target


@pytest.fixture(scope="module")
def other_parser():
    """Agent 3's parser, imported from an extracted tree. Never their working copy."""
    tree = _extract_other()
    if tree is None:
        pytest.skip(
            f"CONSOLIDATION HARNESS DID NOT RUN: {OTHER_BRANCH} is not fetched, or "
            f"{OTHER_MODULE} is absent from it. The shared-coverage question is "
            "unanswered until this runs."
        )
    sys.path.insert(0, str(tree / "apps"))
    try:
        from threat_intelligence.sbom_ingestion import import_sbom
    finally:
        sys.path.remove(str(tree / "apps"))
    return import_sbom


@dataclass
class Outcome:
    """What one parser did with one input, normalised for comparison."""

    parser: str
    accepted: bool
    detail: str = ""
    components: int = 0
    licenses: int = 0
    relationships: int = 0
    has_digest: bool = False
    skipped: int = 0
    complete: bool = False
    problems: list[str] = field(default_factory=list)


def _mine(raw: bytes) -> Outcome:
    from vuln_intel.sbom import SbomError, inventory_from_sbom

    try:
        result = inventory_from_sbom(raw)
    except SbomError as exc:
        return Outcome(parser="vi", accepted=False, detail=str(exc)[:120])
    return Outcome(
        parser="vi",
        accepted=True,
        components=result.component_count,
        licenses=sum(len(v) for v in result.licenses.values()),
        relationships=len(result.relationships),
        has_digest=result.source_sha256 is not None,
        skipped=len(result.skipped),
        complete=result.complete,
    )


def _theirs(import_sbom, raw: bytes) -> Outcome:
    from datetime import datetime, timezone

    try:
        imported = import_sbom(
            raw,
            document_id="compare",
            provenance="differential-harness",
            collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            origin="CALLER_SUPPLIED_UNVERIFIED",
        )
    except Exception as exc:  # their API documents a single SBOMError, but be safe
        return Outcome(parser="a3", accepted=False, detail=f"{type(exc).__name__}: {exc}"[:120])
    inventory = imported.inventory
    return Outcome(
        parser="a3",
        accepted=True,
        components=len(getattr(inventory, "components", ()) or ()),
        licenses=len(getattr(inventory, "licenses", ()) or ()),
        relationships=len(getattr(inventory, "dependencies", ()) or ()),
        has_digest=bool(getattr(imported, "source_sha256", None)),
    )


def _cdx(spec: str, components: list[dict], extra: dict | None = None) -> bytes:
    document: dict = {"bomFormat": "CycloneDX", "specVersion": spec, "components": components}
    document.update(extra or {})
    return json.dumps(document).encode()


_ONE = [
    {
        "bom-ref": "pkg:npm/lodash@4.17.20",
        "name": "lodash",
        "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20",
        "licenses": [{"license": {"id": "MIT"}}],
    }
]


def _spdx(packages: list[dict], version: str = "SPDX-2.3") -> bytes:
    return json.dumps(
        {"spdxVersion": version, "SPDXID": "SPDXRef-DOCUMENT", "packages": packages}
    ).encode()


_SPDX_PKG = [
    {
        "name": "requests",
        "versionInfo": "2.31.0",
        "SPDXID": "SPDXRef-Package-requests",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:pypi/requests@2.31.0",
            }
        ],
    }
]


class TestWhereTheParsersGenuinelyDiffer:
    """Every case here is executed against both parsers, not predicted."""

    def test_cyclonedx_1_5_is_read_by_both(self, other_parser):
        raw = _cdx("1.5", _ONE)
        mine, theirs = _mine(raw), _theirs(other_parser, raw)
        assert mine.accepted and theirs.accepted
        assert mine.components == theirs.components == 1

    @pytest.mark.parametrize("spec", ["1.3", "1.4", "1.6"])
    def test_versions_my_parser_reads_and_theirs_does_not(self, other_parser, spec):
        """A COVERAGE difference: their allow-list is exactly ['1.5'].

        This is the concrete reason a canonical parser cannot simply adopt their
        version rule: three supported CycloneDX versions would stop being read.
        """
        raw = _cdx(spec, _ONE)
        mine, theirs = _mine(raw), _theirs(other_parser, raw)
        assert mine.accepted, f"my parser should read CycloneDX {spec}"
        assert not theirs.accepted, (
            f"their parser unexpectedly read CycloneDX {spec}; if this now passes, "
            "re-measure the coverage gap instead of asserting it"
        )

    @pytest.mark.parametrize("spec", ["1.0", "1.1", "1.2", "9.9"])
    def test_versions_neither_parser_should_read(self, other_parser, spec):
        raw = _cdx(spec, _ONE)
        assert not _mine(raw).accepted
        assert not _theirs(other_parser, raw).accepted

    def test_spdx_2_3_is_read_by_both(self, other_parser):
        raw = _spdx(_SPDX_PKG)
        mine, theirs = _mine(raw), _theirs(other_parser, raw)
        assert mine.accepted and theirs.accepted
        assert mine.components == theirs.components == 1

    def test_spdx_2_2_is_a_coverage_difference(self, other_parser):
        raw = _spdx(_SPDX_PKG, version="SPDX-2.2")
        mine, theirs = _mine(raw), _theirs(other_parser, raw)
        assert mine.accepted, "my parser claims SPDX-2.2; it must read it"
        assert not theirs.accepted

    def test_a_package_without_a_purl_is_a_POLICY_difference(self, other_parser):
        """Both accept the document; they disagree about the component.

        Theirs keeps it with no purl. Mine skips it with a reason and reports the
        inventory as incomplete. Neither is wrong -- but a canonical parser has to
        choose, and that choice determines whether an un-joinable component silently
        enters an inventory. That is an owner decision, not a refactor.
        """
        raw = _spdx([{"name": "mystery", "versionInfo": "1.0", "SPDXID": "SPDXRef-x"}])
        mine, theirs = _mine(raw), _theirs(other_parser, raw)
        assert mine.accepted and theirs.accepted, "both should read the document"
        assert mine.components == 0, "mine skips a purl-less component"
        assert theirs.components == 1, "theirs keeps it"
        assert mine.skipped >= 1, "mine must say why it skipped"
        assert mine.complete is False, "a partial inventory must not claim completeness"

    def test_an_oversized_document_is_refused_by_both(self, other_parser):
        """Both have a byte ceiling; this is SHARED behaviour worth keeping."""
        raw = b'{"bomFormat":"CycloneDX","specVersion":"1.5","x":"' + b"a" * 1_000_001 + b'"}'
        assert not _mine(raw).accepted
        assert not _theirs(other_parser, raw).accepted

    def test_duplicate_json_keys_are_refused_by_both(self, other_parser):
        """Their parser had this first; mine adopted it in M52. SHARED now."""
        raw = b'{"bomFormat":"CycloneDX","specVersion":"1.5","version":"1","version":"2"}'
        assert not _mine(raw).accepted
        assert not _theirs(other_parser, raw).accepted

    def test_a_tag_value_document_is_refused_by_both(self, other_parser):
        """Neither supports SPDX tag-value; the shared answer is 'no'."""
        raw = b"SPDXVersion: SPDX-2.3\nPackageName: x\nPackageVersion: 1\n"
        assert not _mine(raw).accepted
        assert not _theirs(other_parser, raw).accepted

    def test_both_emit_a_document_digest_that_agrees(self, other_parser):
        import hashlib

        raw = _cdx("1.5", _ONE)
        expected = hashlib.sha256(raw).hexdigest()
        from vuln_intel.sbom import inventory_from_sbom

        assert inventory_from_sbom(raw).source_sha256 == expected
        from datetime import datetime, timezone

        imported = other_parser(
            raw, document_id="d", provenance="p",
            collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            origin="CALLER_SUPPLIED_UNVERIFIED",
        )
        assert imported.source_sha256 == expected


class TestTheConsolidationVerdict:
    """The conclusion the harness supports, asserted so it cannot drift from the data."""

    def test_coverage_is_my_superset_and_policy_is_theirs(self, other_parser):
        """Consolidating onto either parser alone would lose something today.

        Adopting their version allow-list loses 1.3/1.4/1.6. Adopting my purl policy
        would drop their purl-less components *without their owners agreeing to it*.
        So the honest recommendation is shared *validation* with per-owner policy,
        which is what the M52 comparison proposed -- now with a test behind each claim.
        """
        versions_i_read_they_do_not = ["1.3", "1.4", "1.6"]
        for spec in versions_i_read_they_do_not:
            raw = _cdx(spec, _ONE)
            assert _mine(raw).accepted and not _theirs(other_parser, raw).accepted

        purl_less = _spdx([{"name": "m", "versionInfo": "1", "SPDXID": "SPDXRef-m"}])
        mine, theirs = _mine(purl_less), _theirs(other_parser, purl_less)
        assert mine.components != theirs.components, (
            "the policy divergence disappeared; re-measure the recommendation"
        )
