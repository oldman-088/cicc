"""All feed entries in these tests are synthetic and never published as real data."""
from datetime import datetime, timezone
import json
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from app.connectors.cisa_kev import parse_snapshot
from app.connectors.cisa_import import import_snapshot
from app.models import Base, Tenant, User, Entity, CisaCatalogRecord, CisaCatalogState, ProvenanceEvent, SecurityAuditEvent
from app.security import hash_password
from app.sessions import issue_session

def fixture_snapshot(*, release='2026-01-01T10:00:00Z', collected=datetime(2026,1,2,tzinfo=timezone.utc), description='Synthetic fixture'):
    doc = {'catalogVersion':'fixture','dateReleased':release,'count':1,'vulnerabilities':[{'cveID':'CVE-2099-0001',
        'vendorProject':'Fixture vendor','product':'Fixture product','vulnerabilityName':'Fixture vulnerability',
        'dateAdded':'2026-01-01','shortDescription':description,'requiredAction':'Fixture only',
        'dueDate':'2026-02-01','knownRansomwareCampaignUse':'Unknown'}]}
    return parse_snapshot(json.dumps(doc).encode(), collected_at=collected)

@pytest.fixture
def env(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path / "import.db"}')
    @event.listens_for(engine, 'connect')
    def fk(connection, _): connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine); factory = sessionmaker(engine, expire_on_commit=False)
    a, b = uuid4(), uuid4()
    with factory.begin() as db:
        db.add_all([Tenant(id=a, name='a'), Tenant(id=b, name='b')]); db.flush()
        for t, role in [(a,'admin'), (a,'viewer'), (b,'admin')]:
            db.add(User(tenant_id=t, username=role, role=role, active=True, password_hash=hash_password('a secure password')))
    with factory.begin() as db:
        a_token = issue_session(db, a, 'admin', 'a secure password')
        b_token = issue_session(db, b, 'admin', 'a secure password')
        viewer = issue_session(db, a, 'viewer', 'a secure password')
    yield factory, a, b, a_token, b_token, viewer
    engine.dispose()

def test_idempotent_import_is_tenant_scoped_and_preserves_analyst_edits(env):
    factory, a, b, admin, other, viewer = env
    snap = fixture_snapshot()
    assert import_snapshot(factory, admin_token=admin, snapshot=snap) == {'created':1, 'changed':0, 'observed':1}
    assert import_snapshot(factory, admin_token=admin, snapshot=snap) == {'created':0, 'changed':0, 'observed':1}
    assert import_snapshot(factory, admin_token=other, snapshot=snap)['created'] == 1
    with pytest.raises(PermissionError): import_snapshot(factory, admin_token=viewer, snapshot=snap)
    with factory.begin() as db:
        rows = list(db.scalars(select(CisaCatalogRecord)))
        assert len(rows) == 2 and {x.tenant_id for x in rows} == {a,b}
        entity = db.get(Entity, next(x.entity_id for x in rows if x.tenant_id == a)); entity.title = 'Analyst title'
        assert len(list(db.scalars(select(ProvenanceEvent).where(ProvenanceEvent.tenant_id == a)))) == 1
    newer = fixture_snapshot(release='2026-01-03T10:00:00Z', collected=datetime(2026,1,4,tzinfo=timezone.utc), description='Updated synthetic fixture')
    assert import_snapshot(factory, admin_token=admin, snapshot=newer)['changed'] == 1
    with factory() as db:
        record = db.scalar(select(CisaCatalogRecord).where(CisaCatalogRecord.tenant_id == a))
        assert db.get(Entity, record.entity_id).title == 'Analyst title'
        assert record.details['description'] == 'Updated synthetic fixture'
        events = list(db.scalars(select(ProvenanceEvent).where(ProvenanceEvent.tenant_id == a)))
        assert len(events) == 2
        assert {event.details['observation']['description'] for event in events} == {'Synthetic fixture', 'Updated synthetic fixture'}
    with pytest.raises(ValueError, match='Older snapshot'): import_snapshot(factory, admin_token=admin, snapshot=snap)

def test_failed_audit_rolls_back_import(env, monkeypatch):
    factory, a, _, admin, _, _ = env
    def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
    monkeypatch.setattr('app.connectors.cisa_import.record_event', fail)
    with pytest.raises(RuntimeError): import_snapshot(factory, admin_token=admin, snapshot=fixture_snapshot())
    with factory() as db:
        assert db.scalar(select(CisaCatalogRecord)) is None
        assert db.get(CisaCatalogState, a) is None
        assert db.scalar(select(Entity)) is None
        assert db.scalar(select(SecurityAuditEvent)) is None

def test_absent_source_item_is_not_deleted_or_treated_as_remediated(env):
    factory, tenant, _, token, _, _ = env
    import_snapshot(factory, admin_token=token, snapshot=fixture_snapshot())
    empty = {'catalogVersion':'fixture-2','dateReleased':'2026-01-03T10:00:00Z','count':0,'vulnerabilities':[]}
    snapshot = parse_snapshot(json.dumps(empty).encode(), collected_at=datetime(2026,1,4,tzinfo=timezone.utc))
    assert import_snapshot(factory, admin_token=token, snapshot=snapshot)['observed'] == 0
    with factory() as db:
        assert db.scalar(select(CisaCatalogRecord).where(CisaCatalogRecord.tenant_id == tenant)) is not None

def test_import_time_budget_rolls_back_partial_changes(env):
    factory, tenant, _, admin, _, _ = env
    calls = iter([0.0, 1.0, 121.0])
    with pytest.raises(TimeoutError, match='time budget'):
        import_snapshot(factory, admin_token=admin, snapshot=fixture_snapshot(), monotonic=lambda:next(calls))
    with factory() as db:
        assert db.scalar(select(CisaCatalogRecord).where(CisaCatalogRecord.tenant_id == tenant)) is None
        assert db.scalar(select(Entity).where(Entity.tenant_id == tenant)) is None
        assert db.get(CisaCatalogState, tenant) is None
        assert not list(db.scalars(select(ProvenanceEvent).where(ProvenanceEvent.tenant_id == tenant)))
