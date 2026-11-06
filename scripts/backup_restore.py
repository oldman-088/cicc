#!/usr/bin/env python3
"""M36 — logical backup / restore / verify for the CICC coordination+ops database.

DB-agnostic (SQLite and PostgreSQL): exports every table of
``app.models.Base.metadata`` to a JSON file with a manifest (row counts,
sha256, sanitized URL — never credentials). Restore recreates the schema on an
empty target DB and re-inserts rows in FK-safe order; it REFUSES to overwrite
a non-empty target unless ``--force`` (reverse-order delete first).

Labels: backup/restore is VERIFIED by automated tests
(apps/api/tests/test_m36_backup_restore.py) against SQLite AND real
PostgreSQL (pgserver). This is a logical backup — see docs/DISASTER_RECOVERY.md
for RPO/RTO and limitations. NOT a production deployment procedure.

Usage:
  python scripts/backup_restore.py backup  --db-url sqlite:///x.db --out backup.json
  python scripts/backup_restore.py verify  --db-url sqlite:///x.db --from backup.json
  python scripts/backup_restore.py restore --db-url sqlite:///y.db --from backup.json [--force]
"""
import argparse
import hashlib
import json
import sys
from datetime import date, datetime, timezone
from decimal import Decimal

sys.path.insert(0, str(__file__ and __import__("pathlib").Path(__file__).resolve().parent.parent / "apps" / "api"))

from sqlalchemy import create_engine, func, make_url, select  # noqa: E402

from app import models  # noqa: E402

FORMAT = "cicc-logical-backup/1"


def _enc(v):
    if isinstance(v, datetime):
        return {"__dt__": v.isoformat()}
    if isinstance(v, date):
        return {"__date__": v.isoformat()}
    if isinstance(v, Decimal):
        return {"__dec__": str(v)}
    if isinstance(v, (bytes, bytearray)):
        import base64
        return {"__b64__": base64.b64encode(bytes(v)).decode()}
    return v


def _dec(v, col):
    from sqlalchemy import Date, DateTime, LargeBinary, Numeric
    if isinstance(v, dict):
        if "__dt__" in v and isinstance(col.type, DateTime):
            return datetime.fromisoformat(v["__dt__"])
        if "__date__" in v and isinstance(col.type, Date) and not isinstance(col.type, DateTime):
            return date.fromisoformat(v["__date__"])
        if "__dec__" in v and isinstance(col.type, Numeric):
            return Decimal(v["__dec__"])
        if "__b64__" in v and isinstance(col.type, LargeBinary):
            import base64
            return base64.b64decode(v["__b64__"])
    return v


def _san(url: str) -> str:
    u = make_url(url)
    return u.set(password=None).render_as_string(hide_password=True)


def export_payload(engine) -> dict:
    payload = {"format": FORMAT, "created_at": datetime.now(timezone.utc).isoformat(), "tables": {}}
    counts = {}
    with engine.connect() as conn:
        for t in models.Base.metadata.sorted_tables:
            cols = [c.name for c in t.columns]
            rows = [[_enc(v) for v in row] for row in conn.execute(t.select())]
            payload["tables"][t.name] = {"columns": cols, "rows": rows}
            counts[t.name] = len(rows)
    return payload, counts


def do_backup(db_url: str, out: str) -> dict:
    engine = create_engine(db_url)
    payload, counts = export_payload(engine)
    engine.dispose()
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    manifest = {
        "format": FORMAT,
        "created_at": payload["created_at"],
        "db": _san(db_url),
        "tables": counts,
        "sha256": hashlib.sha256(body.encode()).hexdigest(),
    }
    doc = {"manifest": manifest, "payload": payload}
    with open(out, "w") as f:
        json.dump(doc, f)
    return manifest


def load_doc(path: str) -> dict:
    with open(path) as f:
        doc = json.load(f)
    if doc.get("manifest", {}).get("format") != FORMAT:
        raise SystemExit("not a cicc-logical-backup/1 file")
    body = json.dumps(doc["payload"], sort_keys=True, separators=(",", ":"))
    if hashlib.sha256(body.encode()).hexdigest() != doc["manifest"]["sha256"]:
        raise SystemExit("sha256 mismatch — backup file corrupted or tampered")
    return doc


def do_verify(db_url: str, path: str) -> dict:
    doc = load_doc(path)
    engine = create_engine(db_url)
    _, counts = export_payload(engine)
    engine.dispose()
    mismatches = {t: (counts.get(t, 0), c) for t, c in doc["manifest"]["tables"].items() if counts.get(t, 0) != c}
    return {"ok": not mismatches, "manifest_tables": doc["manifest"]["tables"], "live_counts": counts, "mismatches": mismatches}


def do_restore(db_url: str, path: str, force: bool = False) -> dict:
    doc = load_doc(path)
    engine = create_engine(db_url)
    models.Base.metadata.create_all(engine)
    with engine.connect() as conn:
        nonempty = []
        for t in models.Base.metadata.sorted_tables:
            n = conn.execute(select(func.count()).select_from(t)).scalar()
            if n:
                nonempty.append((t.name, n))
        if nonempty and not force:
            engine.dispose()
            raise SystemExit(f"REFUSING restore into non-empty DB {nonempty[:5]}... (use --force)")
        if nonempty and force:
            for t in reversed(models.Base.metadata.sorted_tables):
                conn.execute(t.delete())
            conn.commit()
        inserted = {}
        for t in models.Base.metadata.sorted_tables:
            spec = doc["payload"]["tables"].get(t.name)
            if not spec:
                continue
            cols = spec["columns"]
            colmap = {c.name: c for c in t.columns}
            rows = [{c: _dec(v, colmap[c]) for c, v in zip(cols, row)} for row in spec["rows"]]
            if rows:
                conn.execute(t.insert(), rows)
            inserted[t.name] = len(rows)
        conn.commit()
    engine.dispose()
    return {"restored": inserted, "total": sum(inserted.values())}


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in [("backup", None), ("verify", None), ("restore", None)]:
        p = sub.add_parser(name)
        p.add_argument("--db-url", required=True)
        if name in ("backup",):
            p.add_argument("--out", required=True)
        else:
            p.add_argument("--from", dest="frm", required=True)
        if name == "restore":
            p.add_argument("--force", action="store_true")
    args = ap.parse_args()
    if args.cmd == "backup":
        m = do_backup(args.db_url, args.out)
        print(json.dumps({"backup": "ok", **m}, indent=1))
        return 0
    if args.cmd == "verify":
        r = do_verify(args.db_url, args.frm)
        print(json.dumps(r, indent=1, default=str))
        return 0 if r["ok"] else 1
    r = do_restore(args.db_url, args.frm, force=args.force)
    print(json.dumps({"restore": "ok", **r}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
