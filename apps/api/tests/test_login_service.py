from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from app.audit import AuditType
from app.login_service import LoginPolicy, LoginStatus, login, logout
from app.models import Base, Tenant, User, SecurityAuditEvent, AuthSession, RateLimitBucket
from app.security import hash_password
from app.sessions import authenticate_session

@pytest.fixture(autouse=True)
def fixed_rate_limit_clock(monkeypatch):
    # These tests assert behavior within one window, not wall-clock rollover.
    from app import login_service
    original = login_service.consume
    def consume_in_window(*args, **kwargs):
        return original(*args, **kwargs, now=120)
    monkeypatch.setattr(login_service, 'consume', consume_in_window)

@pytest.fixture
def env(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path / "login.db"}', connect_args={'timeout': 30})
    @event.listens_for(engine, 'connect')
    def foreign_keys(conn, _): conn.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id, user_id = uuid4(), uuid4()
    with factory.begin() as db:
        db.add(Tenant(id=tenant_id, name='tenant')); db.flush()
        db.add(User(id=user_id, tenant_id=tenant_id, username='analyst', password_hash=hash_password('a secure password'), role='analyst', active=True))
    yield factory, tenant_id, user_id
    engine.dispose()

def attempt(env, password='a secure password', **kwargs):
    factory, tenant, _ = env
    return login(factory, secret=b'k'*32, tenant_id=tenant, username='analyst', password=password, source_ip='192.0.2.1', **kwargs)

def test_failed_attempts_are_committed_and_throttling_is_audited(env):
    policy = LoginPolicy(account_limit=2, source_limit=10, global_limit=100)
    assert attempt(env, 'wrong', policy=policy).status == LoginStatus.DENIED
    assert attempt(env, 'wrong', policy=policy).status == LoginStatus.DENIED
    assert attempt(env, policy=policy).status == LoginStatus.THROTTLED
    factory, tenant, _ = env
    with factory() as db:
        assert db.scalar(select(RateLimitBucket).where(RateLimitBucket.attempts == 3)) is not None
        assert list(db.scalars(select(SecurityAuditEvent.event_type).where(SecurityAuditEvent.tenant_id == tenant))) == [AuditType.LOGIN_FAILED.value, AuditType.LOGIN_FAILED.value, AuditType.LOGIN_THROTTLED.value]
        assert db.scalar(select(AuthSession)) is None

def test_success_logout_and_audit(env):
    result = attempt(env)
    assert result.status == LoginStatus.SUCCESS and result.token
    factory, _, user = env
    with factory() as db: assert authenticate_session(db, result.token).user_id == user
    assert logout(factory, result.token)
    assert not logout(factory, result.token)
    with factory() as db:
        assert authenticate_session(db, result.token) is None
        assert set(db.scalars(select(SecurityAuditEvent.event_type))) == {'login_succeeded', 'session_revoked'}

def test_audit_failure_rolls_back_session_but_not_throttle(env, monkeypatch):
    def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
    monkeypatch.setattr('app.login_service.record_event', fail)
    with pytest.raises(RuntimeError, match='audit unavailable'): attempt(env)
    factory, _, _ = env
    with factory() as db:
        assert db.scalar(select(AuthSession)) is None
        assert len(list(db.scalars(select(RateLimitBucket)))) == 3

def test_missing_tenant_denied_and_invalid_ip_rejected(env):
    factory, _, _ = env
    result = login(factory, secret=b'k'*32, tenant_id=uuid4(), username='nobody', password='wrong', source_ip='2001:db8::1')
    assert result.status == LoginStatus.DENIED and result.token is None
    with pytest.raises(ValueError): login(factory, secret=b'k'*32, tenant_id=uuid4(), username='x', password='wrong', source_ip='untrusted header')

def test_concurrent_account_limit_sqlite(env):
    policy = LoginPolicy(account_limit=3, source_limit=100, global_limit=100)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: attempt(env, 'wrong', policy=policy).status, range(6)))
    assert results.count(LoginStatus.DENIED) == 3
    assert results.count(LoginStatus.THROTTLED) == 3

def test_broader_throttling_does_not_allocate_unbounded_narrow_buckets(env):
    factory, tenant, _ = env
    policy = LoginPolicy(account_limit=10, source_limit=1, global_limit=3)
    def send(username, ip):
        return login(factory, secret=b'k'*32, tenant_id=tenant, username=username,
                     password='wrong', source_ip=ip, policy=policy).status
    assert send('first', '192.0.2.1') == LoginStatus.DENIED
    assert send('second', '192.0.2.1') == LoginStatus.THROTTLED  # source
    assert send('third', '192.0.2.2') == LoginStatus.DENIED
    for i in range(20):
        assert send(f'unique-{i}', f'198.51.100.{i+1}') == LoginStatus.THROTTLED  # global
    with factory() as db:
        rows = list(db.scalars(select(RateLimitBucket)))
        # One global, two sources and two accounts, no buckets for blocked attempts.
        assert len(rows) == 5
        assert max(row.attempts for row in rows) == policy.global_limit + 1
