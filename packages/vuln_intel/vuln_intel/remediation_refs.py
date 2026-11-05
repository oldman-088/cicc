"""Validated remediation deep links (P0: SSVC/KEV remediation references).

A remediation *link* is only trustworthy if it is a well-formed HTTPS URL from
a named source.  This module therefore:

* validates URI form strictly — scheme must be ``https``, a host is required,
  embedded credentials (``user:pass@host``) are rejected, and control
  characters / whitespace are rejected, so ``javascript:``/``data:``/``file:``
  never pass;
* keeps **source-provided** links (vendor advisory, KEV reference) distinct from
  **calculated** recommendations (our instruction text) — a calculated
  recommendation is never rendered as a link;
* keeps KEV ``requiredAction`` as *text*, never as a link: CISA's instruction is
  prose, and turning it into a URL would fabricate a target;
* deduplicates by normalized URL and records conflicts (same URL claimed with
  different kinds) instead of silently picking one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .kev import KevEntry
from .schema import NormalizedVulnerability, Reference

__all__ = [
    "LINK_KIND_CALCULATED",
    "RemediationLink",
    "collect_remediation_links",
    "validate_link",
]

#: Kind assigned to links we compute ourselves. Never emitted as a URL.
LINK_KIND_CALCULATED = "calculated"

_UNSAFE = re.compile(r"[\x00-\x20<>\"{}|\\^`]")


@dataclass(frozen=True)
class RemediationLink:
    """One validated link with its provenance and kind."""

    url: str
    kind: str  # "vendor_advisory" | "vendor_patch" | "kev_catalogue" | "other_source"
    source: str
    #: False when the URL failed validation — kept visible, never silently dropped.
    valid: bool = True
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "kind": self.kind,
            "source": self.source,
            "valid": self.valid,
            "reason": self.reason,
        }


def validate_link(url: object) -> tuple[bool, str | None]:
    """Return ``(ok, reason)`` for a candidate link. Strict: https + host only."""
    if not isinstance(url, str) or not url.strip():
        return False, "empty or non-string url"
    if _UNSAFE.search(url):
        return False, "control or whitespace characters in url"
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        return False, f"unparseable url: {exc}"
    if parts.scheme != "https":
        return False, f"scheme {parts.scheme!r} is not https"
    if not parts.netloc or "." not in parts.netloc:
        return False, "url has no hostname"
    if parts.username or parts.password:
        return False, "embedded credentials are not allowed in a link"
    return True, None


def _kind_of(reference: Reference) -> str:
    kind = (reference.kind or "").strip().lower()
    if kind in ("advisory", "vendor", "vendor_advisory"):
        return "vendor_advisory"
    if kind in ("patch", "vendor_patch", "fix", "release"):
        return "vendor_patch"
    return "other_source"


def collect_remediation_links(
    record: NormalizedVulnerability,
    *,
    kev_entry: KevEntry | None = None,
) -> tuple[RemediationLink, ...]:
    """Collect validated remediation links for one record.

    Sources: the record's own references (source-provided), plus the KEV
    catalogue entry's canonical advisory URL when a KEV entry is supplied. The
    KEV ``requiredAction`` text is deliberately **not** a link and is returned
    separately by the caller via the entry — it is never URL-ified here.
    Invalid URLs are included with ``valid=False`` and a reason, so a broken
    source link is visible rather than dropped.
    """
    links: list[RemediationLink] = []
    seen: dict[str, str] = {}  # normalized url -> kind
    for ref in record.references:
        ok, reason = validate_link(ref.url)
        key = ref.url.strip().lower()
        kind = _kind_of(ref)
        if key in seen:
            if seen[key] != kind:
                # the conflicting claim is kept visible as its own entry, not dropped
                links.append(
                    RemediationLink(ref.url, kind, ref.source or "unknown", valid=ok,
                                    reason=reason or "conflicting link kind")
                )
            continue  # exact duplicate (same url + kind) collapses
        seen[key] = kind
        links.append(
            RemediationLink(ref.url, kind, ref.source or "unknown", valid=ok, reason=reason)
        )
    if kev_entry is not None:
        url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={kev_entry.cve}"
        ok, reason = validate_link(url)
        links.append(RemediationLink(url, "kev_catalogue", "cisa-kev", valid=ok, reason=reason))
    return tuple(sorted(links, key=lambda l: (not l.valid, l.url)))
