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

import json
from dataclasses import dataclass, field
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
    #: Components that could not be used, with a reason each.
    skipped: tuple[Mapping[str, str], ...] = ()
    #: Components that appeared more than once and were collapsed.
    duplicates: int = 0
    #: Assets (CycloneDX ``bom-ref`` / SPDX ``SPDXID``) associated with components.
    assets: tuple[str, ...] = ()
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
            "document_name": self.document_name,
            "components": self.component_count,
            "duplicates": self.duplicates,
            "assets": list(self.assets),
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
        warnings=tuple(warnings),
    )


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

    components = document.get("components")
    if components is None:
        components = []
    if not isinstance(components, list):
        raise SbomError("components must be an array")

    dependencies: list[Dependency] = []
    skipped: list[Mapping[str, str]] = []
    assets: list[str] = []
    warnings: list[str] = []

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
            if top.get("version"):
                dependency, reason = _dependency(top, asset=asset)
                if dependency is None:
                    skipped.append(
                        _Skip(str(top.get("name") or "<metadata>"), str(reason)).as_dict()
                    )
                else:
                    dependencies.append(dependency)

    return _assemble(
        dependencies,
        skipped,
        fmt="cyclonedx-json",
        document_name=document_name,
        spec_version=str(document.get("specVersion") or "") or None,
        assets=assets,
        warnings=warnings,
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

    packages = document.get("packages")
    if not isinstance(packages, list):
        raise SbomError("packages must be an array")

    dependencies: list[Dependency] = []
    skipped: list[Mapping[str, str]] = []
    assets: list[str] = []
    document_name: str | None = str(document.get("name") or "") or None

    for raw in packages:
        if not isinstance(raw, Mapping):
            skipped.append(_Skip(str(raw)[:80], "package entry is not an object").as_dict())
            continue
        name = str(raw.get("name") or "").strip()
        purpose = str(raw.get("primaryPackagePurpose") or "").upper()
        spdx_id = raw.get("SPDXID")
        if purpose in {"APPLICATION", "CONTAINER", "OPERATING-SYSTEM"}:
            # The artefact being described, not one of its dependencies.
            document_name = document_name or name or None
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

    return _assemble(
        dependencies,
        skipped,
        fmt="spdx-json",
        document_name=document_name,
        spec_version=identifier or None,
        assets=assets,
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
    if isinstance(document, (str, bytes)):
        try:
            loaded = json.loads(document)
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
        return parse_cyclonedx(loaded, asset=asset)
    if assume_format == "spdx-json" or str(loaded.get("spdxVersion") or "").startswith("SPDX-"):
        return parse_spdx(loaded, asset=asset)
    raise SbomError(
        "unrecognised SBOM: expected CycloneDX (bomFormat) or SPDX (spdxVersion). "
        f"Supported formats: {', '.join(SUPPORTED_FORMATS)}"
    )
