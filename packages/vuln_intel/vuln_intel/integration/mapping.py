"""Mapping from ``NormalizedVulnerability`` to the host's storage contract.

Target contract, taken from the CICC API lineage
(``apps/api/app/models.py`` + ``connectors/nvd_import.py`` at
``oldman-088/cicc@arena/da631853-cicc``):

``Entity(kind='vulnerability', title=cve, source=<source>, source_reference=…,
properties={'cve_id': …}, confidence=None, verification_status='unverified')``

``NvdCatalogRecord.details``  — source-specific observation body
``NvdSyncAttempt.status``     — created | succeeded | not_found | failed | abandoned

Design decisions (all reversible, none touching the host):

* **One entity per (tenant, CVE).**  Sources do not each get their own entity;
  the existing NVD importer already keys an entity by CVE and the CISA importer
  does the same, so a third source must join that key rather than fork it.
* **``details`` stays source-shaped.**  The NVD observation body is preserved
  verbatim for NVD (so existing readers keep working); cross-source enrichment
  is added under a separate ``enrichment`` key that this package owns.
* **Nothing is written without provenance.**  Every payload carries a
  ``provenance`` block naming the source, reference, fetch time and transport.
* **Fixture/demo payloads are marked** with ``origin`` and are refused by the
  real store adapters, so a fixture can never land in a production table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from ..schema import NormalizedVulnerability, Origin, Severity, utcnow

__all__ = [
    "ENRICHMENT_KEY",
    "ENTITY_KIND",
    "assert_persistable",
    "event_types",
    "record_origin",
    "to_enrichment",
    "to_entity_payload",
    "to_provenance",
    "to_source_details",
    "to_store_payload",
]

ENTITY_KIND = "vulnerability"

#: Key under which cross-source extras live inside ``details``. Kept distinct so
#: existing NVD-only readers are unaffected.
ENRICHMENT_KEY = "cicc_enrichment"

_SOURCE_LABEL = {
    "nvd": "NVD",
    "osv": "OSV",
    "cisa-kev": "CISA KEV",
    "epss": "FIRST EPSS",
}


def record_origin(record: NormalizedVulnerability) -> str:
    return record.origin.value


def _require_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(timezone.utc)


def to_entity_payload(
    record: NormalizedVulnerability, *, confidence: Any = None
) -> dict[str, Any]:
    """Entity row fields (mirrors ``NvdImport``'s ``Entity(...)`` construction).

    ``Entity.confidence`` is 0-100 in the host schema and is populated from a supplied
    :class:`~vuln_intel.confidence.ConfidenceValue` **only when the provider published
    it**. An internally calculated confidence deliberately does not go here: the host
    column is read as a provider assertion, and writing our own arithmetic into it
    would launder a judgement as a source statement. Computed values stay in the
    enrichment block, where their basis travels with them.
    """
    primary = record.sources[0] if record.sources else "unknown"
    provenance = record.provenance[0] if record.provenance else None
    stored_confidence: int | None = None
    if confidence is not None:
        from ..confidence import ConfidenceBasis

        if (
            getattr(confidence, "basis", None) == ConfidenceBasis.SOURCE_PROVIDED
            and getattr(confidence, "value", None) is not None
        ):
            # 0-1 locally, 0-100 in the host column.
            stored_confidence = round(float(confidence.value) * 100)
    return {
        "kind": ENTITY_KIND,
        "title": str(record.cve),
        "source": _SOURCE_LABEL.get(primary, primary),
        "source_reference": provenance.source_ref if provenance else None,
        "properties": {
            "cve_id": str(record.cve),
            "cve": str(record.cve),
            "origin": record.origin.value,
            "aliases": list(record.aliases),
            "contributing_sources": list(record.sources),
        },
        # The host stores 0-100. NULL unless a provider published the value; see the
        # docstring. Staying NULL is the honest default and the record remains
        # unverified.
        "confidence": stored_confidence,
        "verification_status": record.verification,
    }


def to_source_details(
    record: NormalizedVulnerability,
    *,
    confidence: Any = None,
    freshness: Any = None,
) -> dict[str, Any]:
    """Source-specific ``details`` body plus the cross-source enrichment block.

    The enrichment block never replaces source fields; it sits beside them, so an
    NVD reader that only understands NVD keys continues to work unchanged.
    """
    details: dict[str, Any] = {
        "cve_id": str(record.cve),
        "origin": record.origin.value,
        "published": record.published.isoformat() if record.published else None,
        "last_modified": record.modified.isoformat() if record.modified else None,
        "descriptions": [{"language": "en", "text": record.details}]
        if record.details
        else [],
        "summary": record.summary,
        "severity": (record.effective_severity or Severity.UNKNOWN).value,
        "cvss": [score.as_dict() for score in record.cvss],
        "cwe": list(record.cwe),
        "references": [{"url": r.url, "kind": r.kind} for r in record.references],
        "affected": [
            {
                "ecosystem": a.ecosystem,
                "name": a.name,
                "introduced": a.introduced,
                "fixed": a.fixed,
                "versions": list(a.versions),
                "purl": a.purl,
            }
            for a in record.affected
        ],
        "kev": record.kev,
        "epss": {
            "score": record.epss_score,
            "percentile": record.epss_percentile,
            "model_date": record.epss_model_date,
        },
        "sources": list(record.sources),
        # Structured conflicts, because a UI cannot filter on prose. `conflict_notes`
        # stays alongside it so an existing prose reader keeps working.
        "conflicts": [c.as_dict() for c in record.conflicts],
        "conflict_notes": list(record.conflict_notes),
        "record_status": record.record_status.value if record.record_status else None,
        "withdrawn": record.withdrawn.isoformat() if record.withdrawn else None,
        # Observation freshness, so a reader of `details` does not have to reach into
        # the enrichment block to find out whether this row is current.
        "freshness": freshness.as_dict() if freshness is not None else None,
        "confidence": confidence.as_dict() if confidence is not None else None,
    }
    details[ENRICHMENT_KEY] = to_enrichment(
        record, confidence=confidence, freshness=freshness
    )
    return details


def to_enrichment(
    record: NormalizedVulnerability,
    *,
    confidence: Any = None,
    freshness: Any = None,
    policy: Any = None,
    seen: Any = None,
) -> dict[str, Any]:
    """Fields owned by this package (safe to ignore in host code that predates it).

    ``confidence``, ``freshness``, ``policy`` and ``seen`` are the persistence fix for a
    real defect: :func:`api.shape_record` has always read ``freshness`` and ``policy`` out
    of this block, and **nothing ever wrote them**, so both were permanently ``null``
    through the API. The enrichment block is the documented home for package-owned
    fields, so this is where they belong; the alternative — new columns — would have
    been a host contract change.

    Each accepts an object with ``as_dict()``. ``None`` means "not supplied", which
    renders as ``null`` and must not be read as "fresh" or "zero confidence".
    """
    best = record.best_cvss
    payload: dict[str, Any] = {
        "schema": "cicc.vuln_intel.v1",
        "origin": record.origin.value,
        "contributing_sources": list(record.sources),
        "corroborated": len(set(record.sources)) >= 2,
        "best_cvss": best.as_dict() if best else None,
        "kev": record.kev,
        "kev_date_added": record.kev_date_added.isoformat()
        if record.kev_date_added
        else None,
        "epss": {
            "score": record.epss_score,
            "percentile": record.epss_percentile,
            "model_date": record.epss_model_date,
            "available": record.epss_score is not None,
        },
        "conflicts": [c.as_dict() for c in record.conflicts],
        "conflict_notes": list(record.conflict_notes),
        # Standing: separate from severity, because "critical but withdrawn" and
        # "critical" are different situations for whoever actions the backlog.
        "record_status": record.record_status.value if record.record_status else None,
        "withdrawn": record.withdrawn.isoformat() if record.withdrawn else None,
        "ssvc": dict(record.ssvc),
        "verification": record.verification,
        # Present as explicit nulls rather than omitted: a consumer reading
        # `enrichment["confidence"]` should get null, not a KeyError, and the key's
        # presence tells it the field exists and is unset.
        "confidence": confidence.as_dict() if confidence is not None else None,
        "freshness": freshness.as_dict() if freshness is not None else None,
        "policy": policy.as_dict() if policy is not None else None,
        "seen": seen.as_dict() if seen is not None else None,
    }
    return payload


def to_provenance(
    record: NormalizedVulnerability, *, fetched_at: datetime | None = None
) -> dict[str, Any]:
    """Provenance block, shaped for a ``ProvenanceEvent`` insert.

    ``event_type`` mirrors the host's existing vocabulary
    (``source_record_created`` / ``source_record_updated``).
    """
    stamps = [p.fetched_at for p in record.provenance] or [fetched_at or utcnow()]
    latest = max(_require_aware(s) for s in stamps)
    latest_entry = max(record.provenance, key=lambda p: p.fetched_at) if record.provenance else None
    return {
        "event_type": "source_record_ingested",
        "occurred_at": latest,
        "details": {
            "source": latest_entry.source if latest_entry else "unknown",
            "source_reference": latest_entry.source_ref if latest_entry else None,
            "url": latest_entry.url if latest_entry else None,
            "transport": latest_entry.transport if latest_entry else "unknown",
            "origin": record.origin.value,
            "contributing_sources": list(record.sources),
            "cve_id": str(record.cve),
            "observed_at": latest.isoformat(),
        },
    }


def to_store_payload(
    record: NormalizedVulnerability,
    *,
    tenant_id: str,
    collected_at: datetime | None = None,
    confidence: Any = None,
    freshness: Any = None,
    policy: Any = None,
    seen: Any = None,
) -> dict[str, Any]:
    """Complete payload for :meth:`VulnerabilityStore.upsert`.

    ``confidence``, ``freshness``, ``policy`` and ``seen`` are optional and additive, so
    an existing caller that passes only ``tenant_id`` keeps working and an existing host
    adapter needs no change: the values travel inside the enrichment block, which is
    already part of the payload.
    """
    moment = _require_aware(collected_at or utcnow())
    enrichment = to_enrichment(
        record, confidence=confidence, freshness=freshness, policy=policy, seen=seen
    )
    return {
        "tenant_id": tenant_id,
        "cve": str(record.cve),
        "origin": record.origin.value,
        "entity": to_entity_payload(record, confidence=confidence),
        "details": to_source_details(record, confidence=confidence, freshness=freshness),
        "enrichment": enrichment,
        "provenance": to_provenance(record, fetched_at=moment),
        "collected_at": moment,
    }


def event_types(*, created: bool) -> tuple[str, str]:
    """Return ``(provenance_event_type, audit_action)`` for an upsert outcome.

    Names are aligned with the host's existing ``AuditType`` members so the
    adapter can map them without inventing new vocabulary.
    """
    if created:
        return "source_record_created", "nvd_record_imported"
    return "source_record_updated", "nvd_record_imported"


def assert_persistable(payload: Mapping[str, Any], *, allow_fixture: bool) -> None:
    """Refuse to persist fixture/demo data unless explicitly permitted.

    This is the last line of defence for rule "never present synthetic data as
    verified live intelligence": the store adapter calls it before any write.
    """
    origin = payload.get("origin")
    if origin == Origin.LIVE.value:
        return
    if allow_fixture:
        return
    raise PermissionError(
        f"refusing to persist origin={origin!r} record; "
        "fixture/demo data must not enter production tables"
    )


