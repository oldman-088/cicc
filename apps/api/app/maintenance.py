"""Explicit offline maintenance; no scheduler, no operator identity audit."""
import argparse
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .rate_limit import cleanup_expired_batch
from .sessions import cleanup_expired_sessions_batch

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Delete one batch of expired rate-limit buckets or sessions. Requires a synchronized clock.')
    parser.add_argument('--kind', choices=['rate-limits', 'expired-sessions'], default='rate-limits')
    parser.add_argument('--confirm-cleanup', action='store_true')
    parser.add_argument('--batch-size', type=int, default=1000)
    args = parser.parse_args(argv)
    url = os.environ.get('DATABASE_URL')
    if not url or not args.confirm_cleanup or not 1 <= args.batch_size <= 10000:
        print('DATABASE_URL, explicit confirmation, and batch size 1-10000 are required.', file=sys.stderr)
        return 2
    engine = None
    try:
        engine = create_engine(url, hide_parameters=True)
        if engine.dialect.name != 'postgresql':
            raise ValueError('PostgreSQL required')
        with sessionmaker(engine).begin() as db:
            count = (cleanup_expired_batch(db, batch_size=args.batch_size) if args.kind == 'rate-limits'
                     else cleanup_expired_sessions_batch(db, batch_size=args.batch_size))
    except Exception:
        print('Maintenance failed. Check database access and migrations.', file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    print(f'Deleted {count} {args.kind} records; no scheduler was started.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
