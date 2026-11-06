#!/usr/bin/env python3
"""Safe PR #4 body updater (M28, in response to the M27 accidental empty PATCH).

Procedure:
1. FETCH the current body and preserve it (backup file + variable).
2. Apply a controlled update: append/replace a marked section only.
3. PATCH via REST with the FULL preserved body + update.
4. VERIFY the resulting body (length + required markers) after the PATCH.
Never sends anything unless the fetched body is non-empty (unless --allow-empty).
"""
import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


def gh(*args: str, input_text: str | None = None) -> str:
    r = subprocess.run(["gh", "api", *args], input=input_text, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"gh api failed: {r.stderr[:300]}")
    return r.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--section-file", required=True, help="markdown file with the section to append")
    ap.add_argument("--marker", required=True, help="heading marker, e.g. '## Milestone 28'")
    ap.add_argument("--pr", default="4")
    ap.add_argument("--backup-dir", default=None)
    args = ap.parse_args()

    current = gh(f"repos/oldman-088/cicc/pulls/{args.pr}", "-q", ".body")
    if not current.strip():
        raise SystemExit("REFUSING to PATCH: current PR body is empty — aborting to avoid repeating the M27 wipe.")
    backup_dir = args.backup_dir or tempfile.mkdtemp(prefix="pr-body-backup-")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = f"{backup_dir}/pr{args.pr}-body-{ts}.md"
    with open(backup, "w") as f:
        f.write(current)
    print(f"preserved existing body ({len(current)} chars) -> {backup}")

    section = open(args.section_file).read()
    if args.marker in current:
        # replace existing section from marker to next '## ' heading or end
        idx = current.index(args.marker)
        rest = current[idx + len(args.marker):]
        nxt = rest.find("\n## ")
        body = current[:idx] + section.rstrip() + ("\n" + rest[nxt:] if nxt != -1 else "\n")
    else:
        body = current.rstrip() + "\n\n" + section.rstrip() + "\n"

    payload = json.dumps({"body": body})
    gh("-X", "PATCH", f"repos/oldman-088/cicc/pulls/{args.pr}", "--input", "-", input_text=payload)

    after = gh(f"repos/oldman-088/cicc/pulls/{args.pr}", "-q", ".body")
    if len(after) < len(current) * 0.9:
        raise SystemExit(f"VERIFY FAILED: body shrank {len(current)} -> {len(after)}; restore from {backup}")
    if args.marker not in after:
        raise SystemExit(f"VERIFY FAILED: marker {args.marker!r} missing after PATCH; restore from {backup}")
    print(f"VERIFIED: body {len(current)} -> {len(after)} chars, marker present")


if __name__ == "__main__":
    sys.exit(main())
