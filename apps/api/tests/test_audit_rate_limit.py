from uuid import uuid4
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from app.audit import AuditType, list_events, record_event
from app.models import Base, RateLimitBucket, Tenant
from app.rate_limit import consume
from app.security import Principal, Role

@pytest.fixture
def db():
    engine = create_engine('sqlite:///:memory:')
    @event.listens_for(engine, 'connect')
    def foreign_keys(conn, _): conn.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    with Session(engine) as db: yield db
    engine.dispose()

def test_audit_scope_permissions_and_allowlist(db):
    a, b = Tenant(id=uuid4(), name='a'), Tenant(id=uuid4(), name='b')
    db.add_all([a, b]); db.commit()
    record_event(db, a.id, AuditType.LOGIN_FAILED)
    record_event(db, b.id, AuditType.LOGIN_SUCCEEDED)
    db.commit()
    admin = Principal(uuid4(), a.id, Role.ADMIN)
    assert [x.event_type for x in list_events(db, admin, a.id)] == ['login_failed']
    with pytest.raises(PermissionError): list_events(db, admin, b.id)
    with pytest.raises(PermissionError): list_events(db, Principal(uuid4(), a.id, Role.ANALYST), a.id)
    with pytest.raises(ValueError): record_event(db, a.id, 'password=secret')
    with pytest.raises(ValueError): list_events(db, admin, a.id, 101)

def test_fixed_window_is_atomic_statement_and_keys_are_digested(db):
    kw = dict(secret=b'x'*32, scope='account', identifier='person@example.test', limit=2, window_seconds=60)
    assert consume(db, **kw, now=120)
    assert consume(db, **kw, now=121)
    assert not consume(db, **kw, now=122)
    db.commit()
    bucket = db.scalar(select(RateLimitBucket))
    assert bucket.attempts == 3 and 'person' not in bucket.key_digest
    assert consume(db, **kw, now=180)
    assert consume(db, **{**kw, 'scope':'source'}, now=120)
    with pytest.raises(ValueError): consume(db, **{**kw, 'secret':b'short'}, now=120)

def test_rollback_discards_consumption(db):
    kw = dict(secret=b'x'*32, scope='account', identifier='name', limit=1, window_seconds=60, now=120)
    assert consume(db, **kw)
    db.rollback()
    assert consume(db, **kw)

def test_cleanup_retains_all_potentially_active_windows(db):
    from app.rate_limit import cleanup_expired
    db.add_all([RateLimitBucket(key_digest='a'*64, window_start=1, attempts=1),
                RateLimitBucket(key_digest='b'*64, window_start=2, attempts=1),
                RateLimitBucket(key_digest='c'*64, window_start=86402, attempts=1)])
    db.commit()
    assert cleanup_expired(db, now=86402) == 1
    db.commit()
    assert {x.window_start for x in db.scalars(select(RateLimitBucket))} == {2, 86402}
    with pytest.raises(ValueError): cleanup_expired(db, now=-1)

def test_cleanup_requires_commit(db):
    from app.rate_limit import cleanup_expired
    db.add(RateLimitBucket(key_digest='a'*64, window_start=1, attempts=1)); db.commit()
    assert cleanup_expired(db, now=100000) == 1
    db.rollback()
    assert db.get(RateLimitBucket, ('a'*64, 1)) is not None

def test_bounded_cleanup_retains_boundary_and_rolls_back(db):
    from app.rate_limit import cleanup_expired_batch
    db.add_all([RateLimitBucket(key_digest=f'{i:064x}', window_start=i, attempts=1) for i in range(1,5)])
    db.commit()
    assert cleanup_expired_batch(db, batch_size=2, now=86404) == 2
    db.rollback()
    assert len(list(db.scalars(select(RateLimitBucket)))) == 4
    assert cleanup_expired_batch(db, batch_size=2, now=86404) == 2
    db.commit()
    assert {r.window_start for r in db.scalars(select(RateLimitBucket))} == {3,4}
    assert cleanup_expired_batch(db, batch_size=10000, now=86404) == 1
    with pytest.raises(ValueError): cleanup_expired_batch(db, batch_size=10001)
    with pytest.raises(ValueError): cleanup_expired_batch(db, now=-1)


def test_fixed_window_allows_boundary_burst(db):
    # Fixed windows are intentionally not rolling windows: two full allowances
    # can be consumed in adjacent seconds. Ingress controls are still required.
    kw = dict(secret=b'x'*32, scope='account', identifier='fixture', limit=2, window_seconds=60)
    assert [consume(db, **kw, now=119) for _ in range(3)] == [True, True, False]
    assert [consume(db, **kw, now=120) for _ in range(3)] == [True, True, False]
