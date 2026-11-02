from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models import Base, Tenant, User, AuthSession
from app.security import Role, hash_password
from app.sessions import issue_session, authenticate_session, revoke_session

@pytest.fixture
def db():
    engine = create_engine('sqlite:///:memory:')
    @event.listens_for(engine, 'connect')
    def enable_fk(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()

def test_session_lifecycle_and_no_raw_token_storage(db):
    tenant = Tenant(id=uuid4(), name='test'); db.add(tenant); db.flush()
    user = User(id=uuid4(), tenant_id=tenant.id, username='analyst', password_hash=hash_password('test password long'), role='analyst', active=True)
    db.add(user); db.commit()
    assert issue_session(db, tenant.id, 'analyst', 'bad') is None
    assert issue_session(db, tenant.id, 'missing', 'bad') is None
    assert issue_session(db, uuid4(), 'analyst', 'test password long') is None
    token = issue_session(db, tenant.id, 'analyst', 'test password long'); db.commit()
    row = db.scalar(select(AuthSession))
    assert token and token not in row.token_digest and len(row.token_digest) == 64
    assert authenticate_session(db, token).role == Role.ANALYST
    user.role = 'viewer'; db.commit()
    assert authenticate_session(db, token).role == Role.VIEWER
    user.active = False; db.commit()
    assert authenticate_session(db, token) is None
    user.active = True; db.commit()
    assert revoke_session(db, token); db.commit()
    assert not revoke_session(db, token)
    assert authenticate_session(db, token) is None

def test_expiry_invalid_and_bad_role(db):
    t = Tenant(id=uuid4(), name='t'); db.add(t); db.flush()
    u = User(id=uuid4(), tenant_id=t.id, username='x', password_hash=hash_password('a sufficiently long password'), role='admin', active=True)
    db.add(u); db.commit()
    token = issue_session(db, t.id, 'x', 'a sufficiently long password'); db.commit()
    row = db.scalar(select(AuthSession)); row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1); db.commit()
    assert authenticate_session(db, token) is None
    assert authenticate_session(db, 'é') is None
    u.role = 'unknown'; db.commit()
    assert issue_session(db, t.id, 'x', 'a sufficiently long password') is None

def test_session_cannot_cross_tenants(db):
    a, b = Tenant(id=uuid4(), name='a'), Tenant(id=uuid4(), name='b'); db.add_all([a,b]); db.flush()
    u = User(id=uuid4(), tenant_id=a.id, username='x', password_hash='not-used', role='viewer', active=True); db.add(u); db.flush()
    db.add(AuthSession(tenant_id=b.id, user_id=u.id, token_digest='a'*64, expires_at=datetime.now(timezone.utc)))
    with pytest.raises(IntegrityError): db.commit()
