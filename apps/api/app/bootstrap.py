"""Offline, operator-authorized creation of a new tenant and its initial admin.

This does not expose a registration API and cannot take over an existing tenant.
The database operator is responsible for access control and credential handling.
"""
import argparse
import getpass
import os
import sys
from uuid import UUID
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from .accounts import _USERNAME
from .audit import AuditType, record_event
from .models import Tenant, User
from .security import Role, hash_password

def create_tenant_with_admin(factory: sessionmaker, *, tenant_name: str, username: str, password: str) -> tuple[UUID, UUID]:
    if not tenant_name or tenant_name != tenant_name.strip() or len(tenant_name) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in tenant_name):
        raise ValueError('Invalid tenant name')
    if not _USERNAME.fullmatch(username):
        raise ValueError('Invalid username')
    password_hash = hash_password(password)
    with factory.begin() as db:
        tenant = Tenant(name=tenant_name)
        db.add(tenant); db.flush()
        user = User(tenant_id=tenant.id, username=username, password_hash=password_hash, role=Role.ADMIN.value, active=True)
        db.add(user); db.flush()
        # A bootstrap operation is performed offline by an operator, not by a user session.
        record_event(db, tenant.id, AuditType.TENANT_BOOTSTRAPPED, target_user_id=user.id)
        return tenant.id, user.id

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Create a new tenant and initial admin (offline operation).')
    parser.add_argument('--tenant-name', required=True)
    parser.add_argument('--username', required=True, help='3–64 lowercase ASCII letters, numbers, dot, underscore or hyphen')
    parser.add_argument('--confirm-new-tenant', action='store_true', help='Confirm this creates a new tenant, not an account in an existing tenant')
    args = parser.parse_args(argv)
    url = os.environ.get('DATABASE_URL')
    if not args.confirm_new_tenant or not url:
        print('Explicit confirmation and DATABASE_URL are required.', file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print('An interactive terminal is required for password entry.', file=sys.stderr)
        return 2
    try:
        password = getpass.getpass('Initial administrator password: ')
        confirmation = getpass.getpass('Confirm password: ')
        if password != confirmation:
            print('Passwords do not match.', file=sys.stderr)
            return 2
        engine = create_engine(url, hide_parameters=True)
        if engine.dialect.name == 'sqlite':
            @event.listens_for(engine, 'connect')
            def enable_foreign_keys(connection, _):
                connection.execute('PRAGMA foreign_keys=ON')
        try:
            tenant_id, user_id = create_tenant_with_admin(sessionmaker(engine), tenant_name=args.tenant_name, username=args.username, password=password)
        finally:
            engine.dispose()
    except (Exception, KeyboardInterrupt):
        # Do not leak connection URLs, SQL parameters, passwords or stack traces to the terminal.
        print('Bootstrap failed. Check input, database access and migrations.', file=sys.stderr)
        return 1
    print(f'Created tenant {tenant_id} and administrator {user_id}.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
