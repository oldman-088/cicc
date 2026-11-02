"""Internal transactional import of a single validated NVD observation.

No public endpoint or scheduling is provided. Caller must fetch/parse the
record through the adapter, not construct it from untrusted API input. A source
observation is an unverified assertion, not proof of source authenticity.
The tenant lock serializes imports on PostgreSQL; SQLite is not concurrency-safe.
"""
from datetime import datetime, timezone
import json
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from .nvd_cve import NvdRecord, NvdDescription, NvdError, DETAIL_URL, parse_response
from ..audit import AuditType, record_event
from ..models import Entity, NvdCatalogRecord, ProvenanceEvent, Tenant
from ..security import Permission, authorize
from ..sessions import authenticate_session, authenticate_session_locked

SOURCE = 'NIST National Vulnerability Database'


def _aware(value):
    # SQLite strips time zones from UTC values; PostgreSQL returns aware values.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def import_record(factory: sessionmaker, *, admin_token: str, record: NvdRecord) -> dict:
    if (not isinstance(record, NvdRecord) or not isinstance(record.collected_at, datetime)
        or not isinstance(record.cve_id, str) or not isinstance(record.descriptions, tuple)
        or not all(isinstance(d, NvdDescription) for d in record.descriptions)):
        raise ValueError('Invalid observation')
    if record.source != SOURCE or record.source_reference != DETAIL_URL + record.cve_id:
        raise ValueError('Invalid source attribution')
    # A dataclass can be constructed directly; revalidate its contents before
    # storing anything. This does not prove that it came from the provider.
    try:
        payload = json.dumps({'startIndex': 0, 'totalResults': 1, 'vulnerabilities': [{'cve': {
            'id': record.cve_id, 'published': record.published, 'lastModified': record.last_modified,
            'vulnStatus': record.status, 'descriptions': [
                {'lang': d.language, 'value': d.text} for d in record.descriptions]}}]}).encode('utf-8')
        validated = parse_response(payload, cve_id=record.cve_id, collected_at=record.collected_at)
    except (TypeError, ValueError, UnicodeError, NvdError):
        raise ValueError('Invalid observation') from None
    if validated != record:
        raise ValueError('Invalid observation')
    details = {'cve_id': record.cve_id, 'published': record.published, 'last_modified': record.last_modified,
               'status': record.status, 'descriptions': [{'language': d.language, 'text': d.text} for d in record.descriptions],
               'source': SOURCE, 'source_reference': record.source_reference}
    with factory.begin() as db:
        principal = authenticate_session(db, admin_token)
        if principal is None:
            raise PermissionError('Access denied')
        authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
        tenant = db.scalar(select(Tenant).where(Tenant.id == principal.tenant_id).with_for_update(key_share=True))
        if tenant is None:
            raise PermissionError('Access denied')
        refreshed = authenticate_session_locked(db, admin_token)
        if refreshed is None or refreshed.user_id != principal.user_id:
            raise PermissionError('Access denied')
        authorize(refreshed, tenant.id, Permission.MANAGE_USERS)
        existing = db.scalar(select(NvdCatalogRecord).where(NvdCatalogRecord.tenant_id == tenant.id,
                                                            NvdCatalogRecord.cve_id == record.cve_id))
        if existing is not None:
            current, incoming = _aware(existing.last_collected_at), _aware(record.collected_at)
            if incoming < current or (incoming == current and existing.details != details):
                raise ValueError('Older or conflicting observation cannot overwrite a newer observation')
            changed = existing.details != details
            if changed:
                existing.details = details
            existing.last_collected_at = record.collected_at
            created = False
            entity_id = existing.entity_id
        else:
            entity = Entity(tenant_id=tenant.id, kind='vulnerability', title=record.cve_id, source=SOURCE,
                source_reference=record.source_reference, properties={'cve_id': record.cve_id},
                created_by=principal.user_id, confidence=None, verification_status='unverified',
                collected_at=record.collected_at)
            db.add(entity); db.flush()
            entity_id = entity.id
            db.add(NvdCatalogRecord(tenant_id=tenant.id, entity_id=entity_id, cve_id=record.cve_id,
                details=details, first_collected_at=record.collected_at, last_collected_at=record.collected_at))
            created, changed = True, False
        if created or changed:
            db.add(ProvenanceEvent(tenant_id=tenant.id, entity_id=entity_id, actor_id=principal.user_id,
                event_type='source_record_created' if created else 'source_record_updated',
                details={'source': SOURCE, 'source_reference': record.source_reference, 'cve_id': record.cve_id,
                         'collected_at': record.collected_at.isoformat(), 'observation': details}))
        record_event(db, tenant.id, AuditType.NVD_RECORD_IMPORTED, principal.user_id, target_entity_id=entity_id)
        return {'created': created, 'changed': changed, 'entity_id': entity_id}
