"""Internal import for validated KEV snapshots; no live fetch or public endpoint.

Import locks the tenant row for PostgreSQL concurrency. SQLite has no equivalent
row lock and is only supported for non-concurrent development tests. A snapshot
import is all-or-nothing with its audit and provenance events. Source data is
kept separately from analyst-editable entity fields. Absence from a snapshot is
not interpreted as deletion, remediation, or verification.
"""
from datetime import datetime, timezone
import time
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from .cisa_kev import KevSnapshot, SOURCE, FEED_URL
from ..audit import AuditType, record_event
from ..models import CisaCatalogRecord, CisaCatalogState, CisaSyncAttempt, Entity, ProvenanceEvent, Tenant, User
from ..security import Permission, authorize
from ..sessions import authenticate_session, authenticate_session_locked

def _aware(value):
    # SQLite strips timezone information from timezone-aware columns; timestamps
    # are stored and interpreted as UTC. PostgreSQL returns aware values.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

IMPORT_BUDGET_SECONDS = 120.0

def import_snapshot(factory: sessionmaker, *, admin_token: str, snapshot: KevSnapshot, attempt_id=None, monotonic=time.monotonic) -> dict:
    if not isinstance(snapshot, KevSnapshot) or snapshot.released_at.tzinfo is None or snapshot.released_at.utcoffset() is None or snapshot.collected_at.tzinfo is None or snapshot.collected_at.utcoffset() is None:
        raise ValueError('Invalid snapshot')
    deadline = monotonic() + IMPORT_BUDGET_SECONDS
    def check_budget():
        if monotonic() >= deadline:
            raise TimeoutError('Catalog import time budget exceeded')
    # Reparse the normalized structure is not possible here: callers must use
    # the validating parser; do not expose this internal function to untrusted input.
    with factory.begin() as db:
        principal = authenticate_session(db, admin_token)
        if principal is None:
            raise PermissionError('Access denied')
        authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
        # FOR NO KEY UPDATE still serializes imports without blocking FK KEY SHARE.
        tenant = db.scalar(select(Tenant).where(Tenant.id == principal.tenant_id).with_for_update(key_share=True))
        if tenant is None:
            raise PermissionError('Access denied')
        # Recheck after tenant lock and hold user/session locks through import.
        refreshed = authenticate_session_locked(db, admin_token)
        if refreshed is None or refreshed.user_id != principal.user_id:
            raise PermissionError('Access denied')
        authorize(refreshed, tenant.id, Permission.MANAGE_USERS)
        attempt = None
        if attempt_id is not None:
            attempt = db.scalar(select(CisaSyncAttempt).where(CisaSyncAttempt.id == attempt_id,
                CisaSyncAttempt.tenant_id == tenant.id, CisaSyncAttempt.actor_id == principal.user_id).with_for_update())
            if attempt is None or attempt.status != 'running':
                raise ValueError('Sync attempt is not active')
        state = db.get(CisaCatalogState, tenant.id)
        if state and (_aware(snapshot.released_at) < _aware(state.released_at) or _aware(snapshot.collected_at) < _aware(state.collected_at)):
            raise ValueError('Older snapshot cannot overwrite a newer snapshot')
        created, changed = 0, 0
        for item in snapshot.records:
            check_budget()
            record = db.scalar(select(CisaCatalogRecord).where(CisaCatalogRecord.tenant_id == tenant.id, CisaCatalogRecord.cve_id == item.cve_id))
            details = {'cve_id':item.cve_id, 'name':item.name, 'vendor':item.vendor, 'product':item.product,
                       'description':item.description, 'date_added':item.date_added.isoformat(), 'due_date':item.due_date.isoformat(),
                       'required_action':item.required_action, 'ransomware_use':item.ransomware_use,
                       'source':SOURCE, 'source_reference':FEED_URL}
            if record is None:
                entity = Entity(tenant_id=tenant.id, kind='vulnerability', title=item.cve_id, source=SOURCE,
                                source_reference=FEED_URL, properties={'cve_id':item.cve_id}, created_by=principal.user_id,
                                confidence=None, verification_status='unverified')
                db.add(entity); db.flush()
                record = CisaCatalogRecord(tenant_id=tenant.id, entity_id=entity.id, cve_id=item.cve_id, details=details,
                                           first_collected_at=snapshot.collected_at, last_collected_at=snapshot.collected_at)
                db.add(record); created += 1
                action = 'source_record_created'
            else:
                action = 'source_record_updated' if record.details != details else None
                if action:
                    record.details = details
                    changed += 1
                record.last_collected_at = snapshot.collected_at
            if action:
                db.add(ProvenanceEvent(tenant_id=tenant.id, entity_id=record.entity_id, actor_id=principal.user_id,
                    event_type=action, details={'source':SOURCE, 'source_reference':FEED_URL, 'cve_id':item.cve_id,
                                                'catalog_version':snapshot.catalog_version, 'released_at':snapshot.released_at.isoformat(),
                                                'collected_at':snapshot.collected_at.isoformat(), 'observation':details}))
        check_budget()
        if state is None:
            state = CisaCatalogState(tenant_id=tenant.id, catalog_version=snapshot.catalog_version,
                                     released_at=snapshot.released_at, collected_at=snapshot.collected_at)
            db.add(state)
        else:
            state.catalog_version = snapshot.catalog_version
            state.released_at = snapshot.released_at
            state.collected_at = snapshot.collected_at
        record_event(db, tenant.id, AuditType.CISA_CATALOG_IMPORTED, principal.user_id)
        if attempt is not None:
            attempt.status = 'succeeded'
            attempt.finished_at = datetime.now(timezone.utc)
            record_event(db, tenant.id, AuditType.CISA_SYNC_SUCCEEDED, principal.user_id)
        check_budget()
        return {'created':created, 'changed':changed, 'observed':len(snapshot.records)}
