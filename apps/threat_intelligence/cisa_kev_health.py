"""Read-only operational health of persisted KEV snapshots, not source truth.

Requires trusted worker/operator access; not a tenant API or public endpoint.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal
from sqlalchemy import text
from sqlalchemy.engine import Engine

Origin = Literal['FETCHED_FROM_GITHUB_CISA_REPO', 'EXPERIMENTAL_DEMO_DATA_ONLY']

@dataclass(frozen=True)
class KevHealth:
    origin: Origin
    status: Literal['never_collected', 'within_check_window', 'check_overdue', 'future_check_time']
    as_of: datetime
    max_check_age_seconds: float
    snapshot_id: int | None
    source_release: datetime | None
    collected_at: datetime | None
    checked_at: datetime | None
    check_age_seconds: float | None
    source_release_in_future: bool | None
    entry_count: int | None


def check_health(engine: Engine, *, origin: Origin, as_of: datetime, max_check_age: timedelta) -> KevHealth:
    """Evaluate last *successful check* against caller-supplied time and horizon.

    Missing snapshots, overdue checks and future clock skew are distinct. Source
    release time is retained separately; an on-time check does not establish that
    the source content is current, accurate, or that the worker is running now.
    """
    if origin not in ('FETCHED_FROM_GITHUB_CISA_REPO','EXPERIMENTAL_DEMO_DATA_ONLY'):
        raise ValueError('invalid source origin')
    if engine.dialect.name != 'postgresql':
        raise ValueError('PostgreSQL is required')
    if not isinstance(as_of, datetime) or as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError('as_of must be timezone aware')
    if not isinstance(max_check_age, timedelta) or max_check_age.total_seconds() <= 0:
        raise ValueError('max_check_age must be positive')
    as_of=as_of.astimezone(timezone.utc)
    horizon=max_check_age.total_seconds()
    with engine.connect() as conn:
        row=conn.execute(text('''SELECT id,released_at,collected_at,checked_at,entry_count FROM ti_kev.snapshot
            WHERE origin=:origin ORDER BY id DESC LIMIT 1'''), {'origin':origin}).mappings().first()
    if row is None:
        return KevHealth(origin,'never_collected',as_of,horizon,None,None,None,None,None,None,None)
    age=(as_of-row['checked_at']).total_seconds()
    status='future_check_time' if age < 0 else ('within_check_window' if age <= horizon else 'check_overdue')
    return KevHealth(origin,status,as_of,horizon,row['id'],row['released_at'],row['collected_at'],row['checked_at'],
                     age,row['released_at'] > as_of,row['entry_count'])
