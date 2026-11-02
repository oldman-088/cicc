"""CISA Known Exploited Vulnerabilities feed adapter.

Fetches only the fixed official HTTPS endpoint; redirects and environment proxy
configuration are disabled by default. The adapter does not persist or publish
records, schedule jobs, or imply that a live synchronization has succeeded.
"""
from dataclasses import dataclass
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from math import ceil
import json
import re
import time
from typing import Callable
import httpx

FEED_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
SOURCE = 'CISA Known Exploited Vulnerabilities Catalog'
MAX_FEED_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 100_000
FETCH_BUDGET_SECONDS = 60.0
_CVE = re.compile(r'^CVE-[0-9]{4}-[0-9]{4,}$')

class ConnectorError(Exception):
    """Safe diagnostic with no remote response body or credentials."""

@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    name: str
    vendor: str
    product: str
    description: str
    date_added: date
    due_date: date
    required_action: str
    ransomware_use: str
    source: str = SOURCE
    source_reference: str = FEED_URL

@dataclass(frozen=True)
class KevSnapshot:
    catalog_version: str
    released_at: datetime
    collected_at: datetime
    records: tuple[KevRecord, ...]

def _text(value, field, maximum=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ConnectorError(f'Invalid {field}')
    return value.strip()

def _date(value, field):
    try:
        if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
            raise ValueError()
        return date.fromisoformat(value)
    except ValueError:
        raise ConnectorError(f'Invalid {field}') from None

def parse_snapshot(data: bytes, *, collected_at: datetime) -> KevSnapshot:
    if len(data) > MAX_FEED_BYTES:
        raise ConnectorError('Feed exceeds size limit')
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError('collected_at must be timezone-aware')
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ConnectorError('Invalid feed JSON') from None
    if not isinstance(document, dict):
        raise ConnectorError('Invalid feed document')
    version = _text(document.get('catalogVersion'), 'catalog version', 100)
    try:
        raw_time = _text(document.get('dateReleased'), 'release timestamp', 80)
        released_at = datetime.fromisoformat(raw_time.replace('Z', '+00:00'))
        if released_at.tzinfo is None or released_at.utcoffset() is None:
            raise ValueError()
    except ValueError:
        raise ConnectorError('Invalid release timestamp') from None
    rows = document.get('vulnerabilities')
    count = document.get('count')
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS or type(count) is not int or count != len(rows):
        raise ConnectorError('Invalid feed count')
    records, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise ConnectorError('Invalid feed record')
        cve = _text(row.get('cveID'), 'CVE identifier', 32)
        if not _CVE.fullmatch(cve) or cve in seen:
            raise ConnectorError('Invalid or duplicate CVE identifier')
        seen.add(cve)
        ransomware = _text(row.get('knownRansomwareCampaignUse'), 'ransomware status', 32)
        if ransomware not in ('Known', 'Unknown'):
            raise ConnectorError('Invalid ransomware status')
        records.append(KevRecord(cve_id=cve, name=_text(row.get('vulnerabilityName'), 'name', 500),
            vendor=_text(row.get('vendorProject'), 'vendor', 500), product=_text(row.get('product'), 'product', 500),
            description=_text(row.get('shortDescription'), 'description'), date_added=_date(row.get('dateAdded'), 'date added'),
            due_date=_date(row.get('dueDate'), 'due date'), required_action=_text(row.get('requiredAction'), 'required action'),
            ransomware_use=ransomware))
    return KevSnapshot(version, released_at, collected_at.astimezone(timezone.utc), tuple(records))

def _retry_delay(header: str, attempt: int) -> float:
    if header.isascii() and header.isdigit():
        if len(header) > 9 or int(header) > 10:
            raise ConnectorError('Source retry delay exceeds local limit')
        return float(int(header))
    if header:
        try:
            until = parsedate_to_datetime(header)
            if until.tzinfo is None:
                raise ValueError()
            delay = max(0, ceil((until - datetime.now(timezone.utc)).total_seconds()))
            if delay > 10:
                raise ConnectorError('Source retry delay exceeds local limit')
            return float(delay)
        except (ValueError, TypeError, OverflowError):
            pass
    return float(min(2 ** attempt, 4))

def fetch_snapshot(*, client: httpx.Client | None = None, sleep: Callable[[float], None] = time.sleep,
                   max_attempts: int = 3, monotonic: Callable[[], float] = time.monotonic) -> KevSnapshot:
    if not 1 <= max_attempts <= 3:
        raise ValueError('max_attempts must be between 1 and 3')
    deadline = monotonic() + FETCH_BUDGET_SECONDS
    def remaining() -> float:
        value = deadline - monotonic()
        if value <= 0:
            raise ConnectorError('Source fetch time budget exceeded')
        return value
    owned = client is None
    if client is None:
        client = httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False, trust_env=False)
    try:
        for attempt in range(max_attempts):
            try:
                budget = remaining()
                timeout = httpx.Timeout(min(15.0, budget), connect=min(5.0, budget))
                with client.stream('GET', FEED_URL, headers={'Accept': 'application/json'}, follow_redirects=False, timeout=timeout) as response:
                    remaining()
                    if response.status_code in (429, 500, 502, 503, 504):
                        if attempt + 1 == max_attempts:
                            raise ConnectorError(f'Source temporarily unavailable (HTTP {response.status_code})')
                        retry_after = response.headers.get('Retry-After', '')
                        delay = _retry_delay(retry_after, attempt)
                    elif response.status_code != 200:
                        raise ConnectorError(f'Source returned HTTP {response.status_code}')
                    else:
                        length = response.headers.get('Content-Length')
                        if length and length.isascii() and length.isdigit() and int(length) > MAX_FEED_BYTES:
                            raise ConnectorError('Feed exceeds size limit')
                        chunks, size = [], 0
                        for chunk in response.iter_bytes():
                            remaining()
                            size += len(chunk)
                            if size > MAX_FEED_BYTES:
                                raise ConnectorError('Feed exceeds size limit')
                            chunks.append(chunk)
                        snapshot = parse_snapshot(b''.join(chunks), collected_at=datetime.now(timezone.utc))
                        remaining()
                        return snapshot
            except httpx.RequestError:
                if attempt + 1 == max_attempts:
                    raise ConnectorError('Source connection failed') from None
                delay = min(2 ** attempt, 4)
            if delay >= remaining():
                raise ConnectorError('Source fetch time budget exceeded')
            sleep(delay)
        raise ConnectorError('Source unavailable')
    finally:
        if owned:
            client.close()
