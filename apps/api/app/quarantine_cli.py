"""Read-only, explicitly confirmed local quarantine metadata inventory.

This is not tenant-aware, authenticated, audited, an orphan detector or cleanup.
Only run on a trusted host and private synthetic-data directory.
"""
import argparse
from dataclasses import asdict
import json
import os
import sys
from .evidence_quarantine import inventory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Inspect a bounded prefix of local quarantine metadata without deleting files.')
    parser.add_argument('--confirm-read-only', action='store_true', help='Confirm local metadata inspection')
    parser.add_argument('--max-entries', type=int, default=100, help='Maximum directory entries to examine (1-1000)')
    args = parser.parse_args(argv)
    directory = os.environ.get('CICC_QUARANTINE_DIRECTORY')
    if not args.confirm_read_only or not directory or not 1 <= args.max_entries <= 1000:
        print('CICC_QUARANTINE_DIRECTORY, confirmation, and a limit from 1 to 1000 are required.', file=sys.stderr)
        return 2
    try:
        result = inventory(directory, max_entries=args.max_entries)
    except BlockingIOError:
        print('Quarantine directory is busy; no inventory was produced.', file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        # Do not print paths or exception text; these can disclose configuration.
        print('Quarantine inventory could not be completed.', file=sys.stderr)
        return 1
    output = asdict(result)
    output['notice'] = ('Read-only observed metadata, not a complete scan or proof of orphan status, '
                        'integrity, authenticity, custody, safety or production readiness. '
                        'Advisory locking does not control noncooperating processes.')
    print(json.dumps(output, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
