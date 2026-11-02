"""Interactive explicitly authorized, single-CVE NVD lookup; no scheduler."""
import argparse
import getpass
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .nvd_cve import _cve_id
from .nvd_sync import SyncBusy, synchronize


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Look up one CVE for the tenant of an admin session.')
    parser.add_argument('cve_id', help='CVE identifier, e.g. CVE-2099-0001')
    parser.add_argument('--confirm-live-fetch', action='store_true', help='Confirm a real request to the fixed official NVD endpoint')
    args = parser.parse_args(argv)
    try:
        _cve_id(args.cve_id)
    except ValueError:
        print('Invalid CVE identifier.', file=sys.stderr)
        return 2
    url = os.environ.get('DATABASE_URL')
    if not args.confirm_live_fetch or not url:
        print('DATABASE_URL and explicit live-fetch confirmation are required.', file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print('An interactive terminal is required for the administrator session token.', file=sys.stderr)
        return 2
    engine = None
    try:
        engine = create_engine(url, hide_parameters=True, pool_pre_ping=True)
        if engine.dialect.name != 'postgresql':
            raise ValueError('PostgreSQL required')
        token = getpass.getpass('Administrator session token: ')
        result = synchronize(sessionmaker(engine, expire_on_commit=False), admin_token=token, cve_id=args.cve_id)
    except SyncBusy:
        print('A lookup is already running for this tenant.', file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        # Database URLs, credentials, provider responses and exceptions may be sensitive.
        print('Lookup did not complete. Check source status and operator configuration.', file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    if result['status'] == 'succeeded':
        print(f"Lookup imported an unverified observation; attempt {result['attempt_id']}. Provider and deployment are not live-verified.")
        return 0
    if result['status'] == 'not_found':
        print(f"Lookup returned no record; attempt {result['attempt_id']}. This does not establish vulnerability safety.")
        return 0
    print(f"Lookup did not complete; attempt {result['attempt_id']} status {result['status']}.", file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
