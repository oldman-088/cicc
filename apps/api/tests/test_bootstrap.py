import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from app import bootstrap
from app.audit import AuditType
from app.models import Base, Tenant, User, SecurityAuditEvent
from app.security import Role, verify_password

@pytest.fixture
def factory(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path / "bootstrap.db"}')
    @event.listens_for(engine, 'connect')
    def foreign_keys(conn, _): conn.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()

def test_create_tenant_admin_and_audit(factory):
    tenant_id, user_id = bootstrap.create_tenant_with_admin(factory, tenant_name='Example', username='admin', password='a long safe password')
    with factory() as db:
        user = db.get(User, user_id)
        assert user.tenant_id == tenant_id and user.active and user.role == Role.ADMIN.value
        assert verify_password('a long safe password', user.password_hash)
        event = db.scalar(select(SecurityAuditEvent))
        assert event.event_type == AuditType.TENANT_BOOTSTRAPPED.value and event.actor_id is None and event.target_user_id == user_id

def test_bootstrap_rolls_back_on_audit_failure(factory, monkeypatch):
    def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
    monkeypatch.setattr(bootstrap, 'record_event', fail)
    with pytest.raises(RuntimeError): bootstrap.create_tenant_with_admin(factory, tenant_name='Example', username='admin', password='a long safe password')
    with factory() as db:
        assert db.scalar(select(Tenant)) is None
        assert db.scalar(select(User)) is None

def test_input_rejected_before_creating_tenant(factory):
    for name, user, password in [(' Example','admin','a long safe password'), ('Example','BAD','a long safe password'), ('Example','admin','short')]:
        with pytest.raises(ValueError): bootstrap.create_tenant_with_admin(factory, tenant_name=name, username=user, password=password)
    with factory() as db: assert db.scalar(select(Tenant)) is None

def test_cli_requires_explicit_configuration_and_tty(monkeypatch, capsys):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    assert bootstrap.main(['--tenant-name', 'Example', '--username', 'admin']) == 2
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///not-used.db')
    monkeypatch.setattr(bootstrap.sys.stdin, 'isatty', lambda: False)
    assert bootstrap.main(['--tenant-name', 'Example', '--username', 'admin', '--confirm-new-tenant']) == 2
    assert 'terminal' in capsys.readouterr().err

def test_cli_passwords_do_not_echo_or_appear_in_error(monkeypatch, capsys):
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///not-used.db')
    monkeypatch.setattr(bootstrap.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(bootstrap.sys.stderr, 'isatty', lambda: True)
    responses = iter(['secret password 123', 'different password'])
    monkeypatch.setattr(bootstrap.getpass, 'getpass', lambda _: next(responses))
    assert bootstrap.main(['--tenant-name', 'Example', '--username', 'admin', '--confirm-new-tenant']) == 2
    captured = capsys.readouterr()
    assert 'secret password' not in captured.out + captured.err
    assert 'do not match' in captured.err

def test_cli_success_with_prepared_database(tmp_path, monkeypatch, capsys):
    url = f'sqlite:///{tmp_path / "prepared.db"}'
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    monkeypatch.setenv('DATABASE_URL', url)
    monkeypatch.setattr(bootstrap.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(bootstrap.sys.stderr, 'isatty', lambda: True)
    monkeypatch.setattr(bootstrap.getpass, 'getpass', lambda _: 'a long safe password')
    assert bootstrap.main(['--tenant-name', 'Example', '--username', 'admin', '--confirm-new-tenant']) == 0
    output = capsys.readouterr()
    assert 'Created tenant' in output.out and 'a long safe password' not in output.out + output.err
    engine = create_engine(url)
    with sessionmaker(engine)() as db: assert db.scalar(select(User)).username == 'admin'
    engine.dispose()
