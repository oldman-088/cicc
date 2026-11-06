"""CISA KEV GitHub mirror collector, read-only and independent of persistence.

Fetches only fixed GitHub API endpoints; no arbitrary source URLs or redirects.
Parsing untrusted bytes does not claim verified/live provenance. This collector is
not scheduled or integrated with a host, and makes no source-confidence claim.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from datetime import date, datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

API = 'https://api.github.com/repos/cisagov/kev-data'
METADATA_URL = API + '/contents/known_exploited_vulnerabilities.json?ref=develop'
MAX_API_BYTES = 4_000_000
MAX_CATALOG_BYTES = 3_000_000
SHA_PATTERN = re.compile(r'^[0-9a-f]{40}$')
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')

class CollectionError(Exception):
    """Sanitized collection or validation failure; no response body included."""

class Entry(BaseModel):
    model_config = ConfigDict(extra='allow', frozen=True)
    cveID: str = Field(min_length=13, max_length=64)
    vendorProject: str = Field(min_length=1, max_length=1024)
    product: str = Field(min_length=1, max_length=1024)
    vulnerabilityName: str = Field(min_length=1, max_length=4096)
    dateAdded: date
    shortDescription: str = Field(min_length=1, max_length=16384)
    requiredAction: str = Field(min_length=1, max_length=16384)
    dueDate: date
    knownRansomwareCampaignUse: str = Field(min_length=1, max_length=256)

    @field_validator('cveID')
    @classmethod
    def valid_cve(cls, value):
        if not CVE_PATTERN.fullmatch(value):
            raise ValueError('invalid CVE format')
        return value

class Catalog(BaseModel):
    model_config = ConfigDict(extra='allow', frozen=True)
    title: str = Field(min_length=1, max_length=1024)
    catalogVersion: str = Field(min_length=1, max_length=128)
    dateReleased: datetime
    count: int = Field(ge=0, strict=True)
    vulnerabilities: list[Entry] = Field(max_length=10000)

    @field_validator('dateReleased')
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('release timestamp must be timezone-aware')
        return value

class CollectedCatalog(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    catalog: Catalog
    source_url: str
    github_blob_sha: str
    content_sha256: str
    collected_at: datetime
    origin: Literal['FETCHED_FROM_GITHUB_CISA_REPO', 'EXPERIMENTAL_DEMO_DATA_ONLY']


def _json(raw: bytes):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=reject_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid constant')))
    except (ValueError, UnicodeError, RecursionError):
        raise CollectionError('Invalid JSON content') from None


def parse_catalog(raw: bytes) -> Catalog:
    """Parse untrusted bytes only; no provenance or real-source claim is added."""
    if not isinstance(raw, bytes) or len(raw) > MAX_CATALOG_BYTES:
        raise CollectionError('Catalog input is invalid or too large')
    try:
        catalog = Catalog.model_validate(_json(raw))
        ids = [item.cveID for item in catalog.vulnerabilities]
        if catalog.count != len(ids) or len(set(ids)) != len(ids):
            raise ValueError('count mismatch or duplicate identifier')
        return catalog
    except (ValueError, TypeError):
        raise CollectionError('Catalog schema or integrity validation failed') from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get(url: str, timeout: float) -> bytes:
    request = Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'cicc-threat-intelligence'})
    with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        declared = response.headers.get('Content-Length')
        if declared is not None and (not declared.isdecimal() or int(declared) > MAX_API_BYTES):
            raise CollectionError('Response too large')
        result = response.read(MAX_API_BYTES + 1)
        if len(result) > MAX_API_BYTES:
            raise CollectionError('Response too large')
        return result


def fetch_catalog(*, timeout: float = 10, retries: int = 2, min_interval: float = 0.25,
                  transport=_get, sleep=time.sleep, monotonic=time.monotonic) -> CollectedCatalog:
    """Fetch a pinned Git blob from the CISA GitHub mirror and validate it.

    The injectable transport is test-only. Do not expose it to request inputs.
    Retries and rate limiting apply per call, not globally across workers.
    """
    if not (0 < timeout <= 30 and 0 <= retries <= 3 and 0 <= min_interval <= 5):
        raise ValueError('invalid collection limits')
    last = None
    def request(url):
        nonlocal last
        for attempt in range(retries + 1):
            now = monotonic()
            if last is not None and now - last < min_interval:
                sleep(min_interval - (now - last))
            last = monotonic()
            try:
                return transport(url, timeout)
            except HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504) or attempt == retries:
                    raise CollectionError('GitHub request failed') from None
            except (URLError, TimeoutError, OSError):
                if attempt == retries:
                    raise CollectionError('GitHub request failed') from None
            sleep(min(0.25 * (2 ** attempt), 2.0))
        raise CollectionError('GitHub request failed')

    metadata = _json(request(METADATA_URL))
    if (not isinstance(metadata, dict) or metadata.get('type') != 'file'
        or metadata.get('path') != 'known_exploited_vulnerabilities.json'
        or type(metadata.get('size')) is not int or not 0 <= metadata['size'] <= MAX_CATALOG_BYTES
        or not isinstance(metadata.get('sha'), str) or not SHA_PATTERN.fullmatch(metadata['sha'])):
        raise CollectionError('Invalid GitHub blob metadata')
    sha = metadata['sha']
    blob = _json(request(API + '/git/blobs/' + sha))
    if not isinstance(blob, dict) or blob.get('encoding') != 'base64' or blob.get('sha') != sha or not isinstance(blob.get('content'), str):
        raise CollectionError('Invalid GitHub blob response')
    try:
        encoded = blob['content'].replace('\n', '')
        if len(encoded) > ((MAX_CATALOG_BYTES + 2) // 3) * 4:
            raise CollectionError('Catalog too large')
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise CollectionError('Invalid GitHub blob encoding') from None
    if len(raw) > MAX_CATALOG_BYTES or type(blob.get('size')) is not int or blob['size'] != len(raw) or metadata['size'] != len(raw):
        raise CollectionError('GitHub blob size mismatch')
    # Git blob hash is an integrity check, not independent source authentication.
    computed = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if computed != sha:
        raise CollectionError('GitHub blob digest mismatch')
    catalog = parse_catalog(raw)
    return CollectedCatalog(catalog=catalog, source_url=METADATA_URL, github_blob_sha=sha,
                            content_sha256=hashlib.sha256(raw).hexdigest(), collected_at=datetime.now(timezone.utc),
                            origin='FETCHED_FROM_GITHUB_CISA_REPO' if transport is _get else 'EXPERIMENTAL_DEMO_DATA_ONLY')
