"""Experimental NVD CVE lookup adapter, isolated from storage and scheduling.

Only a single explicitly provided CVE may be queried at the fixed NVD endpoint.
It does not establish source availability, import data, enforce deployment-wide
rate limits, or verify the authenticity of the upstream service's assertions.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import time
from typing import Callable
import httpx

API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
DETAIL_URL = 'https://nvd.nist.gov/vuln/detail/'
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
FETCH_BUDGET_SECONDS = 30.0
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}')
_LANGUAGE = re.compile(r'[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*')

class NvdError(Exception):
    """Sanitized diagnostic; never includes a response body or credentials."""

@dataclass(frozen=True)
class NvdDescription:
    language: str
    text: str

@dataclass(frozen=True)
class NvdRecord:
    cve_id: str
    published: str
    last_modified: str
    status: str
    descriptions: tuple[NvdDescription, ...]
    collected_at: datetime
    source: str
    source_reference: str


def _cve_id(value: str) -> str:
    if not isinstance(value, str) or len(value) > 32 or not _CVE.fullmatch(value):
        raise ValueError('Invalid CVE identifier')
    return value


def _text(value, field, maximum):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum or
        any((ord(c) < 32 and c not in '\n\t\r') or ord(c) == 127 for c in value)):
        raise NvdError(f'Invalid {field}')
    return value.strip()


def _timestamp(value, field):
    value = _text(value, field, 40)
    try:
        # Preserve the source timestamp; do not infer a timezone if not supplied.
        datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise NvdError(f'Invalid {field}') from None
    return value


def parse_response(data: bytes, *, cve_id: str, collected_at: datetime) -> NvdRecord | None:
    cve_id = _cve_id(cve_id)
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError('collected_at must be timezone-aware')
    if len(data) > MAX_RESPONSE_BYTES:
        raise NvdError('Response exceeds size limit')
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise NvdError('Invalid source JSON') from None
    if not isinstance(doc, dict):
        raise NvdError('Invalid source document')
    rows, total, start = doc.get('vulnerabilities'), doc.get('totalResults'), doc.get('startIndex')
    if (not isinstance(rows, list) or type(total) is not int or total not in (0, 1) or
        type(start) is not int or start != 0 or len(rows) != total):
        raise NvdError('Unexpected lookup result count')
    if total == 0:
        return None
    row = rows[0]
    if not isinstance(row, dict) or not isinstance(row.get('cve'), dict):
        raise NvdError('Invalid source record')
    cve = row['cve']
    if cve.get('id') != cve_id:
        raise NvdError('Mismatched CVE identifier')
    descriptions = cve.get('descriptions')
    if not isinstance(descriptions, list) or not 1 <= len(descriptions) <= 50:
        raise NvdError('Invalid descriptions')
    parsed = []
    for item in descriptions:
        if not isinstance(item, dict):
            raise NvdError('Invalid description')
        language = _text(item.get('lang'), 'description language', 35)
        if not _LANGUAGE.fullmatch(language):
            raise NvdError('Invalid description language')
        parsed.append(NvdDescription(language, _text(item.get('value'), 'description', 10000)))
    return NvdRecord(cve_id=cve_id, published=_timestamp(cve.get('published'), 'published timestamp'),
        last_modified=_timestamp(cve.get('lastModified'), 'modified timestamp'),
        status=_text(cve.get('vulnStatus'), 'status', 100), descriptions=tuple(parsed),
        collected_at=collected_at.astimezone(timezone.utc), source='NIST National Vulnerability Database',
        source_reference=DETAIL_URL+cve_id)


def fetch_cve(cve_id: str, *, client: httpx.Client | None = None, monotonic: Callable[[], float] = time.monotonic) -> NvdRecord | None:
    """Make one bounded request; 429/errors fail explicitly, no retries or scheduler."""
    cve_id = _cve_id(cve_id)
    deadline = monotonic() + FETCH_BUDGET_SECONDS
    def remaining():
        seconds = deadline - monotonic()
        if seconds <= 0:
            raise NvdError('Source fetch time budget exceeded')
        return seconds
    owned = client is None
    if client is None:
        client = httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False, trust_env=False)
    try:
        try:
            budget = remaining()
            with client.stream('GET', API_URL, params={'cveId':cve_id, 'resultsPerPage':1, 'startIndex':0},
                               headers={'Accept':'application/json'}, follow_redirects=False,
                               timeout=httpx.Timeout(min(15.0,budget), connect=min(5.0,budget))) as response:
                remaining()
                if response.status_code != 200:
                    raise NvdError(f'Source returned HTTP {response.status_code}')
                length = response.headers.get('Content-Length', '')
                if length.isascii() and length.isdigit() and (len(length) > 12 or int(length) > MAX_RESPONSE_BYTES):
                    raise NvdError('Response exceeds size limit')
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    remaining()
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise NvdError('Response exceeds size limit')
                    chunks.append(chunk)
                result = parse_response(b''.join(chunks), cve_id=cve_id, collected_at=datetime.now(timezone.utc))
                remaining()
                return result
        except httpx.RequestError:
            raise NvdError('Source connection failed') from None
    finally:
        if owned:
            client.close()
