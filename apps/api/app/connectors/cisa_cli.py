"""Interactive, explicitly authorized single-tenant KEV synchronization.

This command is experimental. It uses a previously issued admin bearer token,
never takes a URL or token as an argument, and never starts a scheduler.
"""
import argparse
import getpass
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .cisa_sync import SyncBusy, synchronize

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Synchronize CISA KEV once for the tenant of an admin session.')
    parser.add_argument('--confirm-live-fetch', action='store_true', help='Confirm a real request to the fixed official CISA endpoint')
    args = parser.parse_args(argv)
    url = os.environ.get('DATABASE_URL')
    if not args.confirm_live_fetch or not url:
        print('DATABASE_URL and explicit live-fetch confirmation are required.', file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print('An interactive terminal is required for the administrator session token.', file=sys.stderr)
        return 2
    engine = None
    try:
        token = getpass.getpass('Administrator session token: ')
        engine = create_engine(url, hide_parameters=True, pool_pre_ping=True)
        if engine.dialect.name != 'postgresql':
            raise ValueError('PostgreSQL required')
        result = synchronize(sessionmaker(engine, expire_on_commit=False), admin_token=token)
    except SyncBusy:
        print('Synchronization is already running for this tenant.', file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        # Exceptions and connection URLs can contain secrets; use the status API
        # for persisted sanitized attempt state and explicit recovery.
        print('Synchronization did not complete. Check source status and operator configuration.', file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    if result['status'] != 'succeeded':
        print(f"Synchronization did not complete; attempt {result['attempt_id']} status {result['status']}.", file=sys.stderr)
        return 1
    print(f"Synchronization succeeded; attempt {result['attempt_id']}, observed {result['observed']} records. Verify source and deployment before operational use.")
    return 0

if __name__ == '__main__':
    sys.exit(main())
