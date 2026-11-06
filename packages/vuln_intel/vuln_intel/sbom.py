"""Turn a software bill of materials into an :class:`Inventory`.

Why this exists
---------------
The package could answer "does this advisory affect what we run" given an inventory,
and nothing could produce an inventory. Every consumer had to hand-build one, which in
practice means writing a CycloneDX/SPDX parser — and a home-grown parser is where a
component silently loses its version and the vulnerability report that follows says
"not affected" about something nobody ever checked.

That is the specific failure this module is written against. It is not a validator: it
reads the two formats the Master Prompt names (CycloneDX, SPDX), and it reports
everything it could not use instead of dropping it.

The honesty rule, stated once
-----------------------------
A component with **no version** cannot be matched against any affected range. It must
therefore not enter the inventory silently: the inventory would then look complete while
being unable to answer the question it exists for. Such components are counted in
:attr:`SbomIngestResult.skipped` with a reason, and
:attr:`SbomIngestResult.complete` is ``False`` so a caller can refuse to present the
resulting report as a full assessment.

The same applies to a component whose purl we cannot parse: the ecosystem or name would
have to be guessed, and a guessed ecosystem produces a confident wrong answer rather
than an absent one.

No dependencies
---------------
Both formats are JSON, and both are read with ``json`` from the standard library. SPDX
also has a tag-value serialisation; it is accepted where it is unambiguous, and a
document in that form that cannot be read is an error rather than an empty inventory —
an empty inventory is a *fact* ("nothing is installed"), so it must never be the result
of a parse failure.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence

from .watchlist import Dependency, Inventory, dependency_from_purl

__all__ = [
    "SUPPORTED_FORMATS",
    "SbomError",
    "SbomIngestResult",
    "inventory_from_sbom",
    "parse_cyclonedx",
    "parse_spdx",
]

#: Formats this module reads. Named so a caller can say what is supported without
#: importing and calling the parser.
SUPPORTED_FORMATS = ("cyclonedx-json", "spdx-json", "spdx-tag-value")


#: Hard ceilings on what one document may contain.
#:
#: Found by differential comparison with a second SBOM parser in this repository
#: (``apps/threat_intelligence/sbom_ingestion.py``), which caps bytes and counts and
#: refuses beyond them. Without limits, a caller-supplied document is a denial-of-service
#: vector — nested ``components`` plus nested dependency targets are quadratic, and
#: nothing else in the request path would stop it. The numbers match that parser's
#: ceilings deliberately: two parsers that disagree about what is "too large" disagree
#: about what a valid SBOM is.
MAX_COMPONENTS = 5000
MAX_DEPENDENCIES = 10000
MAX_LICENSES_PER_COMPONENT = 100

#: Ceiling on a document's size in bytes. Matches the second implementation's limit;
#: an unbounded document is a memory-exhaustion vector at a network boundary.
MAX_DOCUMENT_BYTES = 1_000_000


def _no_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    """Reject a document that states the same key twice.

    ``json.loads`` silently keeps the last occurrence, so ``{"version": "1", "version":
    "2"}`` has one meaning to us and another to a stricter reader. Which version was
    scanned is not a detail worth guessing about.
    """
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise SbomError(f"duplicate JSON key {key!r}: the document is ambiguous")
        out[key] = value
    return out


def _no_json_constants(token: str) -> Any:
    """Reject ``NaN``/``Infinity``. They are not JSON, though Python accepts them."""
    raise SbomError(f"invalid JSON constant {token!r}: not valid JSON")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise SbomError(f"non-finite number {value!r} in the document")
    return number


#: CycloneDX spec versions this parser claims to understand. A document declaring any
#: other version is refused rather than read optimistically: the fields this parser
#: relies on are version-dependent, so reading an unknown version produces a plausible
#: and unverified inventory. (Previously every version, including ``9.9``, was accepted
#: silently.)
SUPPORTED_CYCLONEDX_VERSIONS = ("1.3", "1.4", "1.5", "1.6")

#: SPDX versions understood, for the same reason.
SUPPORTED_SPDX_VERSIONS = ("SPDX-2.2", "SPDX-2.3")


class SbomError(ValueError):
    """The document could not be read as an SBOM at all.

    Distinct from "the document was read but some components were unusable": that is a
    result with a populated ``skipped`` tuple, not an exception. A parse failure must
    never degrade into an empty inventory, because an empty inventory asserts that
    nothing is installed.
    """


@dataclass(frozen=True)
class _Skip:
    name: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"component": self.name, "reason": self.reason}


@dataclass(frozen=True)
class SbomIngestResult:
    """An inventory plus a full account of what was left out of it."""

    inventory: Inventory
    #: Format that was detected, one of :data:`SUPPORTED_FORMATS`.
    format: str
    #: ``metadata.component.name`` / SPDX ``name`` when the document carries one.
    document_name: str | None = None
    #: Version of the document (CycloneDX ``specVersion`` or SPDX ``spdxVersion``).
    spec_version: str | None = None
    #: SHA-256 of the exact bytes the document was parsed from, when the caller supplies
    #: them. Adopted in M52 after comparing with ``apps/threat_intelligence/
    #: sbom_ingestion.py``, which binds every licence statement to a document digest.
    #: Without it two documents are indistinguishable in a report, so a finding cannot
    #: be traced back to the artefact that produced it. ``None`` means the caller parsed
    #: the bytes itself and did not say which bytes.
    source_sha256: str | None = None
    #: Components that could not be used, with a reason each.
    skipped: tuple[Mapping[str, str], ...] = ()
    #: Components that appeared more than once and were collapsed.
    duplicates: int = 0
    #: Assets (CycloneDX ``bom-ref`` / SPDX ``SPDXID``) associated with components.
    assets: tuple[str, ...] = ()
    #: Package → licence identifiers, as the document states them. §5.6 asks for
    #: licence information; carrying it here means a consumer does not have to
    #: re-parse the document to answer "what licence is this under".
    licenses: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    #: Directed edges ``(from, to)`` in the declared dependency graph, keyed by
    #: package name as normalised in :attr:`inventory`. §5.6 asks for dependency
    #: relationships; without them an "SBOM" is only a flat list, and "which of my
    #: direct dependencies pulled this in" — the question that decides whether a
    #: finding is urgent — cannot be answered.
    relationships: tuple[tuple[str, str], ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def component_count(self) -> int:
        return len(self.inventory)

    @property
    def complete(self) -> bool:
        """False when any component was unusable, so the inventory is partial.

        A caller that presents a vulnerability report built from a partial inventory as
        a complete assessment is making the claim this property exists to prevent.
        """
        return not self.skipped

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "spec_version": self.spec_version,
            "source_sha256": self.source_sha256,
            "document_name": self.document_name,
            "components": self.component_count,
            "duplicates": self.duplicates,
            "assets": list(self.assets),
            "licenses": {name: list(ids) for name, ids in sorted(self.licenses.items())},
            "relationships": [list(edge) for edge in self.relationships],
            "skipped": [dict(entry) for entry in self.skipped],
            "complete": self.complete,
            "warnings": list(self.warnings),
            "inventory": self.inventory.as_dict(),
        }


def _dependency(entry: Mapping[str, Any], *, asset: str | None):
    """One SBOM component → :class:`Dependency`, or a reason it cannot be one.

    Ordered so the most specific evidence wins: a purl is authoritative when present,
    because it carries ecosystem, name and version in a form both formats agree on.
    """
    purl = entry.get("purl")
    name = str(entry.get("name") or "").strip()
    version = entry.get("version")

    if isinstance(purl, str) and purl.strip():
        parsed = dependency_from_purl(purl.strip(), asset=asset)
        if parsed is not None:
            return parsed, None
        # Fall through: a purl we cannot parse is not a reason to discard a component
        # whose name and version are stated plainly.
        name_version_hint = True
    else:
        name_version_hint = False

    if not name:
        return None, "no name and no usable purl"
    if version is None or str(version).strip() == "":
        # The rule: unusable, loudly. An unversioned component cannot be matched, and
        # an inventory that quietly drops it answers "not affected" for a package it
        # never looked at.
        return None, "no version: the component cannot be matched against any range"
    if not name_version_hint and not entry.get("ecosystem"):
        return None, (
            "no purl and no ecosystem: the ecosystem cannot be derived without guessing"
        )

    return (
        Dependency(
            ecosystem=str(entry.get("ecosystem") or ""),
            name=name,
            version=str(version).strip(),
            asset=asset,
        ),
        None,
    )


def _assemble(
    dependencies: Sequence[Dependency],
    skipped: list[Mapping[str, str]],
    *,
    fmt: str,
    document_name: str | None,
    spec_version: str | None,
    assets: Sequence[str] = (),
    warnings: Sequence[str] = (),
    licenses: Mapping[str, Sequence[str]] | None = None,
    relationships: Sequence[tuple[str, str]] = (),
) -> SbomIngestResult:
    """Deduplicate, preserving order, and count what was collapsed."""
    seen: dict[tuple[str, str, str], Dependency] = {}
    duplicates = 0
    for dependency in dependencies:
        key = (
            dependency.canonical_ecosystem,
            dependency.canonical_name,
            dependency.version,
        )
        if key in seen:
            duplicates += 1
            continue
        seen[key] = dependency
    return SbomIngestResult(
        inventory=Inventory(dependencies=tuple(seen.values())),
        format=fmt,
        document_name=document_name,
        spec_version=spec_version,
        skipped=tuple(skipped),
        duplicates=duplicates,
        assets=tuple(sorted(set(assets))),
        licenses={k: tuple(v) for k, v in (licenses or {}).items()},
        # Edges are de-duplicated but not sorted: the document's order is the only
        # hint about which relationship was declared first, and it costs nothing.
        relationships=tuple(dict.fromkeys(relationships)),
        warnings=tuple(warnings),
    )


def _cyclonedx_licenses(entry: Mapping[str, Any]) -> tuple[str, ...]:
    """Licence identifiers from a CycloneDX component's ``licenses`` array.

    CycloneDX allows either ``{"license": {"id": "Apache-2.0"}}`` or
    ``{"license": {"name": "Apache License 2.0"}}``, and an expression form
    ``{"expression": "MIT OR Apache-2.0"}``. All three are read because picking one
    would silently drop licences from documents that are perfectly valid.
    """
    found: list[str] = []
    raw = entry.get("licenses")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            expression = item.get("expression")
            if isinstance(expression, str) and expression.strip():
                found.append(expression.strip())
                continue
            licence = item.get("license")
            if isinstance(licence, Mapping):
                for key in ("id", "name"):
                    value = licence.get(key)
                    if isinstance(value, str) and value.strip():
                        found.append(value.strip())
                        break
    return tuple(dict.fromkeys(found))


def _spdx_licenses(raw: Mapping[str, Any]) -> tuple[str, ...]:
    """Licence identifiers from an SPDX package.

    ``licenseDeclared`` is what the package *says* it is; ``licenseConcluded`` is what
    the producer concluded. Both are kept, declared first, because a consumer needs to
    know when they disagree — and SPDX uses ``NOASSERTION`` for "not stated", which is
    dropped rather than reported as a licence called NOASSERTION.
    """
    found: list[str] = []
    for key in ("licenseDeclared", "licenseConcluded"):
        value = raw.get(key)
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned and cleaned.upper() not in {"NOASSERTION", "NONE"}:
                found.append(cleaned)
    return tuple(dict.fromkeys(found))


def _graph_key(dependency: Dependency) -> str:
    """The name an edge is recorded under, matching the inventory's own spelling."""
    return dependency.canonical_name


def _cyclonedx_relationships(
    document: Mapping[str, Any], ref_to_name: Mapping[str, str]
) -> tuple[list[tuple[str, str]], list[str]]:
    """Edges from a CycloneDX ``dependencies`` array.

    The array is a list of ``{"ref": X, "dependsOn": [Y, ...]}``. ``ref``/``dependsOn``
    are ``bom-ref`` values, so they are mapped back to package names through the
    inventory. A reference that is not in the inventory is reported as a warning
    rather than dropped: it means the document describes a relationship to something
    it did not describe, which is worth knowing and must not be invented.
    """
    edges: list[tuple[str, str]] = []
    warnings: list[str] = []
    raw = document.get("dependencies")
    if not isinstance(raw, list):
        return edges, warnings
    if len(raw) > MAX_DEPENDENCIES:
        raise SbomError(
            f"too many dependency records: {len(raw)} exceeds the {MAX_DEPENDENCIES} limit"
        )
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        parent_ref = entry.get("ref")
        parent = ref_to_name.get(str(parent_ref)) if parent_ref is not None else None
        if parent is None:
            if parent_ref is not None:
                warnings.append(
                    f"dependency graph references {parent_ref!r}, which is not in the inventory"
                )
            continue
        depends_on = entry.get("dependsOn")
        if not isinstance(depends_on, list):
            continue
        if len(depends_on) > MAX_DEPENDENCIES:
            raise SbomError(
                f"too many dependency targets in one record: {len(depends_on)} exceeds "
                f"the {MAX_DEPENDENCIES} limit"
            )
        for child_ref in depends_on:
            child = ref_to_name.get(str(child_ref))
            if child is None:
                warnings.append(
                    f"{parent} depends on {child_ref!r}, which is not in the inventory"
                )
                continue
            edges.append((parent, child))
    return edges, warnings


def _spdx_relationships(
    document: Mapping[str, Any], ref_to_name: Mapping[str, str]
) -> tuple[list[tuple[str, str]], list[str]]:
    """Edges from an SPDX ``relationships`` array.

    SPDX states ``A DEPENDS_ON B`` and also ``B DEPENDENCY_OF A``; both mean the same
    edge, so both are read. Anything else (``CONTAINS``, ``DESCRIBES``) is left out:
    an SPDX document's ``DESCRIBES`` edge points at the artefact being described, not
    at one of its dependencies, and treating the two as equivalent would put the
    application itself into the dependency graph of its own libraries.
    """
    edges: list[tuple[str, str]] = []
    warnings: list[str] = []
    raw = document.get("relationships")
    if not isinstance(raw, list):
        return edges, warnings
    if len(raw) > MAX_DEPENDENCIES:
        raise SbomError(
            f"too many relationships: {len(raw)} exceeds the {MAX_DEPENDENCIES} limit"
        )
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        kind = str(entry.get("relationshipType") or "").upper()
        left_ref, right_ref = entry.get("spdxElementId"), entry.get("relatedSpdxElement")
        if kind == "DEPENDS_ON":
            parent, child = left_ref, right_ref
        elif kind == "DEPENDENCY_OF":
            parent, child = right_ref, left_ref
        else:
            continue
        parent, child = ref_to_name.get(str(parent)), ref_to_name.get(str(child))
        if parent is None or child is None:
            warning_target = left_ref if parent is None else right_ref
            warnings.append(
                f"{kind} relationship references {warning_target!r}, "
                "which is not in the inventory"
            )
            continue
        edges.append((parent, child))
    return edges, warnings


def parse_cyclonedx(document: Mapping[str, Any], *, asset: str | None = None) -> SbomIngestResult:
    """Read a CycloneDX JSON BOM.

    Components are read from the top-level ``components`` array and, additively, from
    ``metadata.component`` when it declares a version — a BOM describing a single
    application often states the application as the metadata component and everything
    it uses as components.

    Nested ``components`` (a component's own dependencies) are read too, because a
    service's BOM frequently nests. Only the first level of nesting is followed: a full
    recursive walk of an adversarial document is a denial-of-service vector, and a BOM
    that nests deeper than that is unusual enough to be worth refusing rather than
    guessing at.
    """
    if not isinstance(document, Mapping):
        raise SbomError("a CycloneDX BOM must be a JSON object")
    if str(document.get("bomFormat")) != "CycloneDX":
        raise SbomError(
            f"not a CycloneDX document: bomFormat is {document.get('bomFormat')!r}"
        )
    declared_version = document.get("specVersion")
    if declared_version is not None and str(declared_version) not in (
        SUPPORTED_CYCLONEDX_VERSIONS
    ):
        raise SbomError(
            f"unsupported CycloneDX specVersion {declared_version!r}: this parser reads "
            f"{', '.join(SUPPORTED_CYCLONEDX_VERSIONS)}. Reading an unknown version "
            "would produce an inventory nobody has verified."
        )

    components = document.get("components")
    if components is None:
        components = []
    if not isinstance(components, list):
        raise SbomError("components must be an array")
    if len(components) > MAX_COMPONENTS:
        raise SbomError(
            f"too many components: {len(components)} exceeds the {MAX_COMPONENTS} limit"
        )

    dependencies: list[Dependency] = []
    skipped: list[Mapping[str, str]] = []
    assets: list[str] = []
    warnings: list[str] = []
    licenses: dict[str, tuple[str, ...]] = {}
    #: bom-ref -> package name, so the ``dependencies`` array can be resolved.
    ref_to_name: dict[str, str] = {}

    def consume(entries: Sequence[Any], *, depth: int) -> None:
        for raw in entries:
            if not isinstance(raw, Mapping):
                skipped.append(_Skip(str(raw)[:80], "component entry is not an object").as_dict())
                continue
            label = str(raw.get("name") or raw.get("purl") or "<unnamed>")
            component_asset = raw.get("bom-ref") or asset
            dependency, reason = _dependency(raw, asset=component_asset)
            if dependency is None:
                skipped.append(_Skip(label, str(reason)).as_dict())
            else:
                dependencies.append(dependency)
                if component_asset:
                    assets.append(str(component_asset))
                ident = _graph_key(dependency)
                if component_asset:
                    ref_to_name[str(component_asset)] = ident
                found_licences = _cyclonedx_licenses(raw)
                if found_licences:
                    licenses[ident] = found_licences
            nested = raw.get("components")
            if isinstance(nested, list) and nested:
                if depth >= 1:
                    warnings.append(
                        f"{label}: nested components below depth 1 were not read"
                    )
                    continue
                consume(nested, depth=depth + 1)

    consume(components, depth=0)

    metadata = document.get("metadata")
    document_name = None
    if isinstance(metadata, Mapping):
        top = metadata.get("component")
        if isinstance(top, Mapping):
            document_name = str(top.get("name") or "") or None
            # The metadata component is the artefact being described, not one of its
            # dependencies. When it is a usable package it joins the inventory (a
            # BOM describing a single library should still report that library);
            # when it is not -- typically an application with no purl -- that is
            # *expected*, not a defect, so it is not listed in `skipped` and does
            # not make the inventory look partial. Listing it would have made every
            # well-formed application BOM report complete=False.
            if top.get("version"):
                dependency = _dependency(top, asset=asset)[0]
                ident = _graph_key(dependency) if dependency is not None else None
                if dependency is not None and ident is not None:
                    dependencies.append(dependency)
                    found_licences = _cyclonedx_licenses(top)
                    if found_licences:
                        licenses.setdefault(ident, found_licences)
                # Register the described artefact's own bom-ref even when it is not a
                # package: its `dependsOn` list is how the document says which
                # libraries are *direct* dependencies, which is the difference
                # between "we use this" and "something we use pulls this in".
                top_ref = top.get("bom-ref")
                if top_ref and (ident or document_name):
                    ref_to_name[str(top_ref)] = ident or str(document_name)

    edges, graph_warnings = _cyclonedx_relationships(document, ref_to_name)
    return _assemble(
        dependencies,
        skipped,
        fmt="cyclonedx-json",
        document_name=document_name,
        spec_version=str(document.get("specVersion") or "") or None,
        assets=assets,
        warnings=[*warnings, *graph_warnings],
        licenses=licenses,
        relationships=edges,
    )


def parse_spdx(document: Mapping[str, Any], *, asset: str | None = None) -> SbomIngestResult:
    """Read an SPDX 2.x JSON document.

    A package is usable when it is a *library* rather than the document's own
    description package: SPDX emits the thing being described as a package with
    ``primaryPackagePurpose: APPLICATION`` (or ``CONTAINER`` / ``OPERATING-SYSTEM``) and
    the dependencies as ``LIBRARY``. Including the application in its own inventory
    would make it match advisories about itself, which is occasionally right and mostly
    noise, so it is recorded as the document name instead.

    ``externalRefs`` of type ``purl`` are preferred over ``name``/``versionInfo``,
    because SPDX names are often human-readable while a purl carries the ecosystem.
    """
    if not isinstance(document, Mapping):
        raise SbomError("an SPDX document must be a JSON object")
    identifier = str(document.get("spdxVersion") or "")
    if not identifier.startswith("SPDX-"):
        raise SbomError(f"not an SPDX document: spdxVersion is {document.get('spdxVersion')!r}")
    declared_spdx = str(document.get("spdxVersion"))
    if declared_spdx not in SUPPORTED_SPDX_VERSIONS:
        raise SbomError(
            f"unsupported spdxVersion {declared_spdx!r}: this parser reads "
            f"{', '.join(SUPPORTED_SPDX_VERSIONS)}"
        )

    packages = document.get("packages")
    if not isinstance(packages, list):
        raise SbomError("packages must be an array")
    if len(packages) > MAX_COMPONENTS:
        raise SbomError(
            f"too many packages: {len(packages)} exceeds the {MAX_COMPONENTS} limit"
        )

    dependencies: list[Dependency] = []
    skipped: list[Mapping[str, str]] = []
    assets: list[str] = []
    licenses: dict[str, tuple[str, ...]] = {}
    #: SPDXID -> package name, so ``relationships`` can be resolved.
    ref_to_name: dict[str, str] = {}
    document_name: str | None = str(document.get("name") or "") or None

    for raw in packages:
        if not isinstance(raw, Mapping):
            skipped.append(_Skip(str(raw)[:80], "package entry is not an object").as_dict())
            continue
        name = str(raw.get("name") or "").strip()
        purpose = str(raw.get("primaryPackagePurpose") or "").upper()
        spdx_id = raw.get("SPDXID")
        if purpose in {"APPLICATION", "CONTAINER", "OPERATING-SYSTEM"}:
            # The artefact being described, not one of its dependencies. Its SPDXID
            # is still registered, because `relationships` uses that id to say which
            # packages are *direct* dependencies of it — resolving those would fail
            # for every well-formed SPDX document otherwise.
            document_name = document_name or name or None
            if spdx_id:
                ref_to_name[str(spdx_id)] = name or str(document_name or spdx_id)
            continue

        purl: str | None = None
        external = raw.get("externalRefs")
        if isinstance(external, list):
            for reference in external:
                if not isinstance(reference, Mapping):
                    continue
                if str(reference.get("referenceType") or "") == "purl":
                    candidate = reference.get("referenceLocator")
                    if isinstance(candidate, str) and candidate.strip():
                        purl = candidate.strip()
                        break

        entry: dict[str, Any] = {
            "name": name,
            "version": raw.get("versionInfo"),
        }
        if purl:
            entry["purl"] = purl
        dependency, reason = _dependency(entry, asset=(str(spdx_id) if spdx_id else asset))
        if dependency is None:
            skipped.append(_Skip(name or "<unnamed>", str(reason)).as_dict())
        else:
            dependencies.append(dependency)
            if spdx_id:
                assets.append(str(spdx_id))
            ident = _graph_key(dependency)
            if spdx_id:
                ref_to_name[str(spdx_id)] = ident
            found_licences = _spdx_licenses(raw)
            if found_licences:
                licenses[ident] = found_licences

    edges, graph_warnings = _spdx_relationships(document, ref_to_name)
    return _assemble(
        dependencies,
        skipped,
        fmt="spdx-json",
        document_name=document_name,
        spec_version=identifier or None,
        assets=assets,
        warnings=graph_warnings,
        licenses=licenses,
        relationships=edges,
    )


def inventory_from_sbom(
    document: Mapping[str, Any] | str | bytes,
    *,
    asset: str | None = None,
    assume_format: str | None = None,
) -> SbomIngestResult:
    """Detect the format and parse it.

    Accepts a parsed mapping or raw JSON text. A document that cannot be identified is
    an :class:`SbomError`, never an empty inventory: "nothing is installed" is a claim,
    and a parse failure must not be able to make it.
    """
    digest: str | None = None
    if isinstance(document, (str, bytes)):
        raw = document.encode("utf-8") if isinstance(document, str) else document
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise SbomError(
                f"the document is {len(raw)} bytes, which exceeds the "
                f"{MAX_DOCUMENT_BYTES} byte limit"
            )
        # Digest the exact bytes, so a result can be traced to one artefact. This is the
        # one property adopted from the second implementation in this repository; see
        # docs/vulnerability-intelligence/SBOM_PARSER_COMPARISON.md.
        digest = hashlib.sha256(raw).hexdigest()
        try:
            loaded = json.loads(
                raw,
                object_pairs_hook=_no_duplicate_keys,
                parse_constant=_no_json_constants,
                parse_float=_finite_float,
            )
        except SbomError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SbomError(
                f"the document is not JSON, and only JSON SBOMs are read: {exc}. "
                "An unreadable document is an error, not an empty inventory."
            ) from exc
    else:
        loaded = document

    if not isinstance(loaded, Mapping):
        raise SbomError("an SBOM must be a JSON object")

    if assume_format == "cyclonedx-json" or str(loaded.get("bomFormat")) == "CycloneDX":
        result = parse_cyclonedx(loaded, asset=asset)
    elif assume_format == "spdx-json" or str(loaded.get("spdxVersion") or "").startswith("SPDX-"):
        result = parse_spdx(loaded, asset=asset)
    else:
        raise SbomError(
            "unrecognised SBOM: expected CycloneDX (bomFormat) or SPDX (spdxVersion). "
            f"Supported formats: {', '.join(SUPPORTED_FORMATS)}"
        )
    if digest is not None and result.source_sha256 is None:
        result = replace(result, source_sha256=digest)
    return result
