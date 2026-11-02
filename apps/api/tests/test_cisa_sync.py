from uuid import uuid4
import pytest
from sqlalchemy import select
from test_cisa_import import env, fixture_snapshot
from app.connectors.cisa_kev import ConnectorError
from app.connectors.cisa_sync import SyncBusy, abandon_sync, begin_sync, get_status, synchronize
from app.models import CisaSyncAttempt, CisaCatalogRecord, SecurityAuditEvent

def test_success_failure_and_tenant_status(env):
    factory, a, b, admin, other, viewer = env
    assert get_status(factory, admin_token=admin)['last_attempt'] is None
    result = synchronize(factory, admin_token=admin, fetch=fixture_snapshot)
    assert result['status'] == 'succeeded' and result['created'] == 1
    status = get_status(factory, admin_token=admin)
    assert status['last_attempt']['status'] == 'succeeded' and status['last_imported_snapshot_collected_at'] is not None
    def failed(): raise ConnectorError('source unavailable, secret detail')
    result = synchronize(factory, admin_token=admin, fetch=failed)
    assert result['status'] == 'failed' and result['error_code'] == 'fetch_failed'
    status = get_status(factory, admin_token=admin)
    assert status['last_attempt']['status'] == 'failed' and status['last_attempt']['error_code'] == 'fetch_failed'
    assert status['last_imported_snapshot_collected_at'] is not None
    assert 'secret detail' not in str(status)
    assert get_status(factory, admin_token=other)['last_attempt'] is None
    with pytest.raises(PermissionError): get_status(factory, admin_token=viewer)
    with factory() as db:
        types = list(db.scalars(select(SecurityAuditEvent.event_type).where(SecurityAuditEvent.tenant_id == a)))
        assert {'cisa_sync_started','cisa_sync_succeeded','cisa_sync_failed','cisa_status_read'} <= set(types)
        assert len(list(db.scalars(select(CisaCatalogRecord)))) == 1

def test_busy_abandon_and_wrong_tenant(env):
    factory, _, _, admin, other, viewer = env
    attempt = begin_sync(factory, admin_token=admin)
    with pytest.raises(SyncBusy): begin_sync(factory, admin_token=admin)
    assert not abandon_sync(factory, admin_token=other, attempt_id=attempt)
    with pytest.raises(PermissionError): begin_sync(factory, admin_token=viewer)
    assert abandon_sync(factory, admin_token=admin, attempt_id=attempt)
    assert get_status(factory, admin_token=admin)['last_attempt']['status'] == 'abandoned'
    assert not abandon_sync(factory, admin_token=admin, attempt_id=attempt)
    assert begin_sync(factory, admin_token=admin) != attempt

def test_abandoned_worker_cannot_commit_a_late_snapshot(env):
    factory, tenant, _, admin, _, _ = env
    def fetch():
        with factory() as db: attempt = db.scalar(select(CisaSyncAttempt).where(CisaSyncAttempt.tenant_id == tenant))
        assert abandon_sync(factory, admin_token=admin, attempt_id=attempt.id)
        return fixture_snapshot()
    with pytest.raises(ValueError, match='not active'): synchronize(factory, admin_token=admin, fetch=fetch)
    with factory() as db:
        assert db.scalar(select(CisaCatalogRecord)) is None
        assert db.scalar(select(CisaSyncAttempt)).status == 'abandoned'

def test_unexpected_fetch_failure_is_recorded_without_details(env):
    factory, _, _, admin, _, _ = env
    def fetch(): raise RuntimeError('private details')
    with pytest.raises(RuntimeError): synchronize(factory, admin_token=admin, fetch=fetch)
    status = get_status(factory, admin_token=admin)
    assert status['last_attempt']['status'] == 'failed' and status['last_attempt']['error_code'] == 'fetch_failed'
    assert 'private details' not in str(status)

def test_import_failure_records_failure_without_partial_data(env, monkeypatch):
    factory, _, _, admin, _, _ = env
    def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
    monkeypatch.setattr('app.connectors.cisa_import.record_event', fail)
    with pytest.raises(RuntimeError): synchronize(factory, admin_token=admin, fetch=fixture_snapshot)
    status = get_status(factory, admin_token=admin)
    assert status['last_attempt']['status'] == 'failed' and status['last_attempt']['error_code'] == 'import_failed'
    assert status['last_imported_snapshot_collected_at'] is None
    with factory() as db: assert db.scalar(select(CisaCatalogRecord)) is None
