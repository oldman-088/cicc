from uuid import uuid4
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from app.accounts import create_user, change_role, disable_user
from app.audit import AuditType
from app.models import Base, Tenant, User, SecurityAuditEvent
from app.security import Role, hash_password
from app.sessions import issue_session, authenticate_session

@pytest.fixture
def ctx(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path / "accounts.db"}')
    @event.listens_for(engine, 'connect')
    def foreign_keys(conn, _): conn.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    a, b = uuid4(), uuid4()
    with factory.begin() as db:
        db.add_all([Tenant(id=a, name='a'), Tenant(id=b, name='b')]); db.flush()
        for tenant, username, role in [(a,'admin','admin'), (a,'viewer','viewer'), (b,'other','analyst')]:
            db.add(User(tenant_id=tenant, username=username, password_hash=hash_password('test password long'), role=role, active=True))
    with factory.begin() as db:
        tokens = {name: issue_session(db, tenant, name, 'test password long') for tenant, name in [(a,'admin'), (a,'viewer'), (b,'other')]}
        ids = {u.username:u.id for u in db.scalars(select(User))}
    yield factory, a, b, tokens, ids
    engine.dispose()

def test_create_change_disable_and_audit(ctx):
    factory, tenant, _, tokens, ids = ctx
    new = create_user(factory, admin_token=tokens['admin'], username='new.analyst', password='another long password', role=Role.ANALYST)
    with factory.begin() as db:
        token = issue_session(db, tenant, 'new.analyst', 'another long password')
        assert authenticate_session(db, token).role == Role.ANALYST
    change_role(factory, admin_token=tokens['admin'], user_id=new, role=Role.VIEWER)
    with factory() as db: assert authenticate_session(db, token).role == Role.VIEWER
    disable_user(factory, admin_token=tokens['admin'], user_id=new)
    with factory.begin() as db:
        assert authenticate_session(db, token) is None
        # Even a future re-enable must not resurrect old sessions.
        db.get(User, new).active = True
    with factory() as db:
        assert authenticate_session(db, token) is None
        events = list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.target_user_id == new)))
        assert {e.event_type for e in events} == {AuditType.USER_CREATED.value, AuditType.USER_ROLE_CHANGED.value, AuditType.USER_DISABLED.value}
        assert all(e.actor_id == ids['admin'] and e.tenant_id == tenant for e in events)

def test_permissions_cross_tenant_and_self_protection(ctx):
    factory, _, _, tokens, ids = ctx
    with pytest.raises(PermissionError): create_user(factory, admin_token=tokens['viewer'], username='valid', password='a long password', role=Role.VIEWER)
    with pytest.raises(PermissionError): change_role(factory, admin_token=tokens['admin'], user_id=ids['other'], role=Role.ADMIN)
    with pytest.raises(PermissionError): disable_user(factory, admin_token=tokens['admin'], user_id=ids['admin'])
    with pytest.raises(PermissionError): disable_user(factory, admin_token='not-a-session', user_id=ids['viewer'])
    with pytest.raises(ValueError): create_user(factory, admin_token=tokens['admin'], username='UPPER', password='a long password', role=Role.VIEWER)
    with pytest.raises(ValueError): create_user(factory, admin_token=tokens['admin'], username='valid', password='short', role=Role.VIEWER)
    with pytest.raises(IntegrityError): create_user(factory, admin_token=tokens['admin'], username='viewer', password='a long password', role=Role.VIEWER)

def test_audit_failure_rolls_back_account(ctx, monkeypatch):
    factory, _, _, tokens, _ = ctx
    def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
    monkeypatch.setattr('app.accounts.record_event', fail)
    with pytest.raises(RuntimeError): create_user(factory, admin_token=tokens['admin'], username='should-not-exist', password='a long password', role=Role.VIEWER)
    with factory() as db: assert db.scalar(select(User).where(User.username == 'should-not-exist')) is None

def test_unauthorized_account_creation_does_not_hash_password(ctx, monkeypatch):
    factory, _, _, tokens, _ = ctx
    def must_not_hash(password):
        raise AssertionError('unauthorized hashing')
    monkeypatch.setattr('app.accounts.hash_password', must_not_hash)
    for token in ['not-a-session', tokens['viewer']]:
        with pytest.raises(PermissionError):
            create_user(factory, admin_token=token, username='valid', password='a long password', role=Role.VIEWER)

def test_admin_revoked_during_password_hash_does_not_create_user(ctx, monkeypatch):
    from app.login_service import logout
    factory, _, _, tokens, _ = ctx
    original = hash_password
    def revoke_then_hash(password):
        assert logout(factory, tokens['admin'])
        return original(password)
    monkeypatch.setattr('app.accounts.hash_password', revoke_then_hash)
    with pytest.raises(PermissionError):
        create_user(factory, admin_token=tokens['admin'], username='valid', password='a long password', role=Role.VIEWER)
    with factory() as db:
        assert db.scalar(select(User).where(User.username == 'valid')) is None
