from uuid import uuid4
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models import Base, Tenant, Entity, Relationship
from app.intelligence import list_entities
from app.security import Principal, Role, Permission, authorize, hash_password, verify_password

@pytest.fixture
def db():
    engine = create_engine('sqlite:///:memory:')
    @event.listens_for(engine, 'connect')
    def foreign_keys(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()

def test_password_hash_and_verification():
    password = 'long enough password'
    encoded = hash_password(password)
    assert password not in encoded and encoded.startswith('$argon2id$')
    assert verify_password(password, encoded)
    assert not verify_password('wrong password', encoded)
    assert not verify_password(password, 'invalid')
    with pytest.raises(ValueError):
        hash_password('short')

def test_authorization_denies_wrong_tenant_and_privilege():
    tenant, other = uuid4(), uuid4()
    viewer = Principal(uuid4(), tenant, Role.VIEWER)
    authorize(viewer, tenant, Permission.READ_INTELLIGENCE)
    with pytest.raises(PermissionError): authorize(viewer, tenant, Permission.WRITE_INTELLIGENCE)
    with pytest.raises(PermissionError): authorize(viewer, other, Permission.READ_INTELLIGENCE)
    with pytest.raises(PermissionError): authorize(Principal(uuid4(), tenant, 'unknown'), tenant, Permission.READ_INTELLIGENCE)

def test_tenant_filtered_reads_and_foreign_key_isolation(db):
    a, b = Tenant(id=uuid4(), name='a'), Tenant(id=uuid4(), name='b')
    db.add_all([a, b]); db.flush()
    first = Entity(id=uuid4(), tenant_id=a.id, kind='indicator', title='first', source='test')
    second = Entity(id=uuid4(), tenant_id=b.id, kind='indicator', title='second', source='test')
    db.add_all([first, second]); db.commit()
    user = Principal(uuid4(), a.id, Role.ANALYST)
    assert [e.id for e in list_entities(db, user, a.id)] == [first.id]
    with pytest.raises(PermissionError): list_entities(db, user, b.id)
    db.add(Relationship(tenant_id=a.id, subject_id=first.id, object_id=second.id, kind='RELATED_TO', source='test'))
    with pytest.raises(IntegrityError): db.commit()
    db.rollback()

def test_entity_creator_and_confidence_constraints(db):
    from app.models import User
    a, b = Tenant(id=uuid4(), name='a'), Tenant(id=uuid4(), name='b')
    db.add_all([a,b]); db.flush()
    user = User(id=uuid4(), tenant_id=b.id, username='other', password_hash='not-used', role='viewer', active=True)
    db.add(user); db.commit()
    db.add(Entity(tenant_id=a.id, created_by=user.id, kind='indicator', title='bad tenant', source='test'))
    with pytest.raises(IntegrityError): db.commit()
    db.rollback()
    db.add(Entity(tenant_id=a.id, kind='indicator', title='bad score', source='test', confidence=101))
    with pytest.raises(IntegrityError): db.commit()
    db.rollback()
