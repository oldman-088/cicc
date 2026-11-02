# Disaster recovery

**Production recovery remains unverified.** No persistent backup system, encrypted off-site storage, operator runbook, retention, RPO/RTO or scheduled drills are implemented. No real deployment or production dataset has been restored. Do not infer operational recoverability from the test below.

## Isolated synthetic logical restore drill

On a trusted Linux developer machine with the Python 3.11 locked API dev requirements and optional `pgserver==0.1.4`, run from the repository root:

```sh
python scripts/test_restore.py
```

This creates two temporary local PostgreSQL instances using local trust authentication, migrates the source, inserts only synthetic records, uses the `pgserver`-bundled `pg_dump` and `pg_restore`, checks restored schema parity with Alembic, verifies selected rows and a tenant constraint, then stops the servers and deletes the temporary archive. It does not accept external database URLs or real data. This is a narrow logical dump/restore test, not backup encryption, off-site durability, point-in-time recovery, production topology, permissions recovery, integrity of arbitrary data, measured RPO/RTO, or an operational recovery procedure. The optional test tool is not covered by the Python application lock.

Future deployment must establish encrypted off-site backups, access controls, retention, recovery point and time objectives, isolated restores, integrity validation and scheduled recovery drills. Never claim recoverability without verification on the actual deployed system.
