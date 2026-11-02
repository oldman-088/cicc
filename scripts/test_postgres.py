#!/usr/bin/env python3
"""Run the API suite on an isolated throwaway PostgreSQL, never a supplied URL.

Optional developer dependency: pgserver==0.1.4. pgserver initializes a private
Unix-socket-only instance with local trust authentication, so use it only on a
trusted machine. The server is stopped before the temporary directory is removed.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

try:
    from pgserver import PostgresServer
except ImportError:
    sys.exit('Install the optional test-only dependency: pip install pgserver==0.1.4')

ROOT = Path(__file__).resolve().parents[1]

def main():
    with tempfile.TemporaryDirectory(prefix='cicc-pg-') as directory:
        server = PostgresServer(Path(directory), cleanup_mode='stop')
        try:
            env = os.environ.copy()
            env['TEST_DATABASE_URL'] = server.get_uri().replace('postgresql://', 'postgresql+psycopg://', 1)
            return subprocess.run([sys.executable, '-m', 'pytest', '-q'], cwd=ROOT / 'apps/api', env=env).returncode
        finally:
            server.cleanup()

if __name__ == '__main__':
    sys.exit(main())
