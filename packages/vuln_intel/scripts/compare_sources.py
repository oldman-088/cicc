#!/usr/bin/env python3
"""Compare host-side and package-side vulnerability records, read-only.

This is the operator's entry point to :mod:`vuln_intel.integration.comparison`. It
opens each database with ``mode=ro`` and runs no statement other than ``SELECT``. It
prints (or writes) a JSON report and exits non-zero when the two sides disagree, so it
can be run in a pipeline without a human reading the output.

Usage
-----
    python scripts/compare_sources.py \
        --host-db /var/lib/cicc/host.db \
        --package-db /var/lib/cicc/vuln_intel.db \
        --stale-after 86400 \
        --output comparison.json

    # Both sides may also be dumps already fetched by whoever owns each database:
    python scripts/compare_sources.py --host-json host.json --package-json pkg.json

Exit codes
----------
    0  the two sides agree as far as the four shared fields are concerned
    1  at least one genuine disagreement
    2  nothing could be compared (bad input, empty input)

It never writes to either side. The SQLite connections are opened read-only, and the
JSON route touches no database at all. There is no ``--fix``, ``--apply`` or
``--reconcile`` flag, because choosing which side is right is the owner's decision.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vuln_intel.integration.comparison import compare_records

#: The columns read from each side. Listing them explicitly keeps the query from
#: widening as either schema grows, and keeps the utility comparing what it documents.
_HOST_QUERY = (
    "SELECT cve_id, details, first_collected_at, last_collected_at "
    "FROM nvd_catalog_records"
)
_PACKAGE_QUERY = "SELECT cve, details, origin, collected_at FROM vulnerability_record"


def _connect_read_only(path: str) -> sqlite3.Connection:
    """Open a SQLite database so that writes are impossible, not merely unwise."""
    uri = f"file:{Path(path).resolve()}?mode=ro"
    # `uri=True` plus mode=ro: SQLite itself refuses any write statement.
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _rows(path: str, query: str) -> list[dict[str, Any]]:
    conn = _connect_read_only(path)
    try:
        out = []
        for row in conn.execute(query):
            record = dict(row)
            raw = record.get("details")
            if isinstance(raw, str):
                try:
                    record["details"] = json.loads(raw)
                except ValueError:
                    # Leave it as text: the comparison will report it as unusable
                    # rather than pretending the row is fine.
                    record["details"] = {"_unparsed": raw}
            out.append(record)
        return out
    finally:
        conn.close()


def _load_json(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("records") or data.get("rows") or []
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a list of records")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only comparison of host and package vulnerability records."
    )
    parser.add_argument("--host-db", help="SQLite file containing nvd_catalog_records")
    parser.add_argument(
        "--package-db", help="SQLite file containing vulnerability_record"
    )
    parser.add_argument("--host-json", help="host rows already exported as JSON")
    parser.add_argument("--package-json", help="package rows already exported as JSON")
    parser.add_argument(
        "--stale-after",
        type=int,
        default=0,
        help=(
            "seconds of difference before one side is called stale; 0 (the default) "
            "disables the judgement, since the two sides are collected by different "
            "jobs and some gap is always present"
        ),
    )
    parser.add_argument("--output", help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    if not (args.host_db or args.host_json):
        parser.error("give --host-db or --host-json")
    if not (args.package_db or args.package_json):
        parser.error("give --package-db or --package-json")

    host_rows = (
        _load_json(args.host_json) if args.host_json else _rows(args.host_db, _HOST_QUERY)
    )
    package_rows = (
        _load_json(args.package_json)
        if args.package_json
        else _rows(args.package_db, _PACKAGE_QUERY)
    )

    report = compare_records(
        host_rows=host_rows,
        package_rows=package_rows,
        stale_threshold_seconds=args.stale_after,
    )
    body = report.as_dict()
    text = json.dumps(body, indent=2, sort_keys=True)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)

    totals = body["totals"]

    # A null on one side is its own finding, not a footnote: it means a reader of that
    # side gets no answer where the other side has one. Reported separately so it is
    # actionable without scanning per-record verdicts.
    if totals["null_fields"]:
        print(
            f"{totals['null_fields']} field(s) recorded by one side and null on the "
            "other (see null_fields)",
            file=sys.stderr,
        )

    if totals["compared"] == 0:
        print(
            "nothing compared: both sides were empty or every row was unusable",
            file=sys.stderr,
        )
        return 2
    if totals["conflicting"]:
        print(
            f"{totals['conflicting']} record(s) disagree on shared fields",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
