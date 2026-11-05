# CTIS 2.0 JSON Schemas — provenance

**Source:** <https://github.com/openctemio/ctis>, directory `schemas/v2/`
**Retrieved:** 2026-11-04 from branch `main`
**Licence:** Apache-2.0 (the CTIS repository states the schema is Apache-2.0 while the
OpenCTEM platform is GPL-3.0; these files come from the `ctis` repository)
**Schema id:** `https://schemas.openctem.io/ctis/2.0/finding.json`

## Why the files are vendored

The interoperability adapter (`vuln_intel/interop/ctis.py`) claims to emit documents
that CTIS accepts. That claim is only worth something if it is checked against the
**real** schema rather than against a hand-written approximation of it.

Vendoring keeps the check reproducible and offline:

- the test must pass in CI with no network access;
- CTIS is not published to PyPI, so there is no package to depend on;
- the runtime package stays stdlib-only — `jsonschema` is a **test** dependency.

## Files

| File | Bytes | Contains |
| --- | --- | --- |
| `finding.json` | 48,885 | The finding object we emit |
| `report.json` | 18,897 | The report envelope |
| `asset.json` | 28,016 | Referenced by `report.json` |
| `dependency.json` | 3,447 | Referenced by `report.json` |
| `endpoint.json` | 3,873 | Referenced by both |
| `evidence-item.json` | 7,662 | Referenced by `finding.json` |
| `web3-finding.json` | 17,054 | Referenced by `finding.json` (web3 profile) |
| `web3-asset.json` | 17,054 | Referenced by `report.json` |

Every file is unmodified. `report.json` and `finding.json` reference each other by
absolute `$id`, so the whole set must be present for validation to resolve — this is
why the unused-looking web3 files are here.

## Updating

CTIS is versioned (`2.0`); a schema change that breaks our output should be a
deliberate decision, not a silent one. To update:

1. re-fetch `schemas/v2/*.json` from the commit you intend to target;
2. record the commit SHA in this file;
3. update `to_ctis_report`'s declared `version` if the major changed;
4. run `pytest tests/test_interop_ctis.py` — the validator is the specification.

If `jsonschema` is not installed the validation tests **skip** rather than pass
silently, and the schema-free structural tests still run.
