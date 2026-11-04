# CICC Vulnerability Intelligence (`packages/vuln_intel`)

Self-contained vulnerability-intelligence layer covering the full lifecycle:
**NVD** and **OSV** collection, **CISA KEV** exploitation evidence, an **EPSS**
integration interface, ecosystem-aware **affected-version evaluation**,
**cross-source correlation**, transparent **prioritization**, actionable
**remediation**, and dependency **exposure analysis**.

- Package: `vuln_intel` (distribution name `cicc-vuln-intel`), version `0.1.0`
- Size: 33 source modules, 21 test modules, **466 tests**
- Status: **IMPLEMENTED and TESTED offline; integration layer ready; NOT live-verified**
- Runtime dependencies: **none** (stdlib only). `httpx` is required only for
  live collection, via the optional `live` extra.

> **Verification statement.** No test in this package touches the network. The
> sandbox where it was written cannot reach `services.nvd.nist.gov` or
> `api.osv.dev`, so *no live integration is claimed*. `nvd.LAST_VERIFIED_LIVE`
> and `osv.LAST_VERIFIED_LIVE` are `None`, and
> `connectors.epss.LIVE_PROVIDER_AVAILABLE` is `False`. Changing those values
> requires a recorded, successful real fetch.

---

## 1. Why this shape

The platform's existing shared modules (`sources.py`, `main.py`, `models.py`)
are **not touched or imported**. This package is a plain library, which means:

- it can be reviewed without a database, a web server or a scheduler;
- it can be adopted by the API layer incrementally (one endpoint at a time);
- it introduces no new dependency pins into the API container.

`tests/test_isolation.py` enforces this: it fails if the package ever imports a
shared module, a web/ORM framework, or a network library outside
`transport.py`.

## 2. Layout

```
packages/vuln_intel/
├── vuln_intel/
│   ├── __init__.py         public surface
│   ├── errors.py           error taxonomy + credential-safe `sanitize`
│   ├── transport.py        Transport protocol, HttpxTransport (real network)
│   ├── retry.py            bounded retry/backoff honouring Retry-After
│   ├── ratelimit.py        client-side rate gates (NVD/OSV quotas)
│   ├── schema.py           CveId, Origin, CvssScore, NormalizedVulnerability…
│   ├── cvss.py             CVSS v3.0/v3.1 base-score computation
│   ├── connectors/
│   │   ├── nvd.py          NVD API 2.0 connector
│   │   ├── osv.py          OSV v1 connector
│   │   └── epss.py         EPSS interface + strict parser (no HTTP call)
│   ├── kev.py              CISA KEV catalogue + stale-preserving cache
│   ├── circuit.py          per-source circuit breaker
│   ├── pipeline.py         collect → observe → merge → KEV → EPSS → rank
│   ├── normalization.py    cross-source merge, KEV signals, EPSS attach
│   ├── priorities.py       additive 0-100 ranking with explanations
│   │
│   │   ── intelligence layer ─────────────────────────────────────────────
│   ├── versions.py         version ordering: semver, PEP440, deb, rpm, maven, go
│   ├── affected.py         three-valued "is this version affected?"
│   ├── correlation.py      identity resolution and cross-source deduplication
│   ├── remediation.py      actionable plans, KEV due dates, upgrade cost
│   ├── watchlist.py        dependency inventory × advisory exposure
│   ├── assessment.py       end-to-end report: collect→correlate→rank→remediate
│   ├── sync.py             incremental NVD sync with a safe checkpoint
│   │
│   │   ── operations ─────────────────────────────────────────────────────
│   ├── config.py           env settings; `Secret` masks itself everywhere
│   ├── health.py           readiness/health report + metrics (no I/O)
│   ├── demo.py             offline pipeline demo (fixtures only)
│   └── integration/
│       ├── contracts.py    VulnerabilityStore / AuditPort protocols
│       ├── mapping.py      record → host entity + details + enrichment
│       ├── service.py      origin gate, dry-run, audit coupling
│       ├── store.py        reference store + deny-by-default store
│       ├── observations.py append-only, source-specific evidence log
│       └── preview.py      review artifact + separation-rule validation
├── tests/                  466 tests, synthetic fixtures only, sockets blocked
│   └── fixtures/           hand-written payloads shaped after public docs
├── pyproject.toml
└── README.md
```

## 3. Quick start (offline)

```bash
cd packages/vuln_intel
python -m pytest              # 153 passed, no network
python -m vuln_intel.demo     # writes vuln_intel/DEMO_OUTPUT.json
```

## 4. Using the connectors

Both connectors require an explicit transport. **There is no default network
client** — omitting one produces an error, never silent empty data.

```python
from vuln_intel import HttpxTransport, NvdConnector, OsvConnector, Origin

nvd = NvdConnector(transport=HttpxTransport())          # live, unverified here
record = nvd.get_cve("CVE-2021-44228")                  # raises SourceNotFound if absent

osv = OsvConnector(transport=HttpxTransport())
record, advisory = osv.get_vulnerability("GHSA-xxxx-xxxx-xxxx")
if record is None:
    ...  # advisory-only: no CVE alias exists; nothing is invented
```

In tests, inject a scripted transport instead:

```python
from vuln_intel.retry import RetryPolicy
from vuln_intel.ratelimit import RateGate

nvd = NvdConnector(
    transport=FakeTransport([response(payload)]),
    gate=RateGate(min_interval=0.0),
    retry=RetryPolicy(attempts=1),
    origin=Origin.FIXTURE,
)
```

### NVD

| Method | Behaviour |
|---|---|
| `get_cve(id)` | one CVE; `SourceNotFound` when NVD has no record |
| `search(start_index, results_per_page)` | one page → `CollectionResult` |
| `search_all()` | bounded paging (`max_pages`), warns that it is **not** a mirror |

- API key is sent as an `apiKey` **header**, never in a URL, so it cannot leak
  into provenance or logs.
- Rate gate pre-empts the documented quota (5 req/30 s without key, 50 with).
- Naive NVD timestamps are read as UTC (documented NVD behaviour).

### OSV

| Method | Behaviour |
|---|---|
| `get_vulnerability(id)` | `(record, advisory)` — exactly one is `None` |
| `lookup_cve(cve)` | rejects a response about a different CVE |
| `collect(ids)` | per-id failures accumulate as `PARTIAL` + warnings |

- An OSV record with **no CVE alias** stays an `AdvisoryOnly`; no CVE is invented.
- `withdrawn` records are surfaced and annotated, not silently dropped.
- Version ranges are preserved verbatim — no ecosystem version comparison is
  attempted (that needs per-ecosystem ordering and is out of scope).

## 5. Unified CVE normalization

`NormalizedVulnerability` is the single cross-source shape. Two invariants are
structural:

1. **Origin is explicit** — `LIVE`, `FIXTURE` or `DEMO`. `merge_records` and
   `normalize_sources` raise `MixedOriginError` if origins differ, and
   `attach_epss` refuses to put fixture EPSS numbers on a live record.
2. **Absence is explicit** — a missing score is `None`, never `0.0`; an
   unassessable vector yields `CvssScore(assessed=False)` instead of a guess.

Conflict handling is conservative: the highest severity is kept (a downgrade
must be a human decision), and every disagreement is appended to
`conflict_notes` rather than overwriting data silently.

```python
from vuln_intel.normalization import normalize_sources, index_kev, attach_kev, attach_epss

merged = normalize_sources([nvd_record, osv_record])       # dict["CVE-…", record]
kev = index_kev(cisa_catalog_payload)                      # dict["CVE-…", KevSignal]
record = attach_kev(merged["CVE-2026-0001"], kev.get("CVE-2026-0001"))
record = attach_epss(record, epss_score_or_none)
```

`attach_kev(record, None)` leaves `kev=None` (**unknown**) and records that the
catalogue was not consulted — absence of KEV data is never rendered as "not
exploited".

### Configuration actually governs behaviour

`assembly.build_connectors(settings)` turns validated `Settings` into the NVD,
OSV and KEV connectors. Before it existed, `config.py` parsed and validated
environment variables that nothing read: an operator could set
`CICC_VULN_NVD_MAX_PAGES=50`, see it echoed at startup, and get defaults instead.

Guarantees:

- **construction performs no I/O** — the first request happens when the caller
  issues one;
- a live transport is installed **only** when `CICC_VULN_LIVE_COLLECTION=true`,
  and enabling it without a transport **raises** rather than building connectors
  that would return `NOT_CONFIGURED` for every call;
- a factory returning `None` is rejected for the same reason;
- each connector gets its **own** transport, so one provider's breaker and pool
  state cannot affect another's;
- the NVD key is unwrapped from `Secret` in exactly one place and never appears in
  `describe()`, `startup_report()`, a repr or an error message (asserted).

`OsvConnector.query_batch()` implements `POST /v1/querybatch` per the official
contract, including **per-query** pagination (only entries that return a
`next_page_token` are retried, and the follow-up resends the same query with the
token). Results are ordered to match the input per the documentation; a
result-count mismatch **raises** rather than risk attributing an advisory id to
the wrong package. The endpoint returns ids and a `modified` timestamp only — it is
a lookup index, not intelligence, so full records still come from
`get_vulnerability()`.

`nvd_window_fetcher()` adapts `NvdConnector.search` to `sync.WindowFetcher`, which
is what makes real incremental coverage possible: `search_all()` reads a bounded
slice of the *current* catalogue, while a fetcher driven by `IncrementalSync` walks
`lastModStartDate`/`lastModEndDate` windows from a persisted watermark, so repeated
runs converge on a complete local view. A failed page is returned as an **error**,
never as an empty window — an empty window would let the checkpoint advance over
data that was never read.

`nvd_collector()` and `osv_collector()` adapt the connectors to the pipeline's
collector protocol. They exist mostly for one reason: a **failed** collection
raises, so the pipeline records `FAILED` with the provider's error, while a
genuinely empty answer returns `[]` and is recorded as "an empty answer, not a
failure". Swallowing a 403 into `[]` would turn an outage into a claim that the
provider has nothing to report.

### CVSS is recomputed, not trusted

`schema.cvss_from_source` prefers the vector and computes the score locally:
CVSS v3.0/v3.1 via `cvss.py` (FIRST spec incl. Appendix-A rounding) and CVSS
v4.0 via `cvss40.py` (macrovector lookup + interpolation, spec v1.2). When a
source's stated `baseScore` disagrees with its own vector, the computed value
wins **and** the disagreement is recorded. CVSS v2 vectors are kept as evidence
but marked `assessed=False` — never scored with v3 or v4 maths.

v4.0 is scored by its own module because it is not a revision of v3: it replaces
the formula entirely, and v3 and v4 scores are **not comparable**. `best_cvss`
therefore prefers v4 over v3 when a record carries both, and never selects v2.

The v4 implementation is validated against vectors and scores published by FIRST
in the CVSS v4.0 Examples document, covering base, threat, environmental and
supplemental scoring. The 270-entry macrovector table is reproduced verbatim
from FIRST's reference implementation (BSD-2-Clause, attributed in the module
header); deriving it by hand would reintroduce transcription risk.

## 6. EPSS integration interface

EPSS is designed in, but the HTTP call is deliberately **not implemented**:

- `EpssProvider` — protocol a live provider must satisfy;
- `EpssCache` / `InMemoryEpssCache` — cache seam (injectable clock);
- `parse_epss_response` — strict parser for the documented FIRST payload
  (`{"status": "OK", "version": …, "data": [{"cve", "epss", "percentile", "date"}]}`);
- `FixtureEpssProvider` — deterministic fixture/demo scores stamped `origin="fixture"`;
- `UnavailableEpssProvider` — default; **raises** instead of returning zeros.

Wiring a live provider later requires no change to scoring code.

## 7. Prioritization

`score_vulnerability` / `rank_vulnerabilities` produce a deterministic 0-100 score
with a per-component breakdown and human-readable reasons.

| Component | Max | Source |
|---|---|---|
| `severity` | 40 | CVSS base score / 10 |
| `exploitation` | 30 | CISA KEV (full) > EPSS (≤ 20) > unknown (neutral 10) |
| `exposure` | 10 | caller-supplied `PriorityContext.exposure` |
| `business` | 10 | caller-supplied `business_criticality` |
| `recency` | 5 | modification/publication age |
| `confidence` | 5 | number of corroborating sources |

Properties enforced by tests:

- KEV membership always outranks even a perfect EPSS forecast (EPSS is a
  prediction, KEV is a confirmed observation);
- unknown exploitation status is *neutral and flagged*, never treated as safe;
- unassessed context factors are excluded with an explicit reason, not assumed
  zero-risk-and-fine;
- demo/fixture rankings carry a warning so they cannot be mistaken for a
  production queue;
- identical inputs produce identical output; ties break on (KEV, EPSS, CVE).

## 8. Reliability and evidence

### Circuit breaker (`circuit.py`)

Retry handles a blip; the breaker handles a sustained outage. After
`failure_threshold` consecutive `SourceError`s a source is **open**: calls fail
fast with `CircuitOpen` and a `retry_in`, so a collector cannot hammer a dead
provider. After the cooldown a single probe is allowed (`half_open`); success
closes it, failure re-opens with a doubled cooldown (capped). Programming errors
(`TypeError`, `KeyError`) are **not** counted — bugs stay visible.

### Append-only evidence (`integration/observations.py`)

A merged `NormalizedVulnerability` is a *derived view*, not evidence. Ingestion
therefore records **one observation per source record**:

| property | guarantee |
|---|---|
| history | never rewritten; a changed source record appends a new row |
| idempotency | `(tenant, source, cve, sha256(payload))` stored once |
| identity | source, source reference, collection time, origin, digest all retained |
| replay order | deterministic: `(collected_at, source, digest)` |
| tenancy | strictly per-tenant |
| origin gate | fixture/demo refused unless the log explicitly allows them |

`to_observations()` splits a merged record into its contributing sources, each
carrying only the fields that source can vouch for (e.g. affected ranges from
OSV, CWE from NVD), so claims stay separable.

### Pipeline (`pipeline.py`)

`EnrichmentPipeline.run()` composes collectors → observation log → merge → KEV →
EPSS → ranking and returns a `PipelineReport` with:

- a `complete` flag that is `False` whenever **any** source failed or any
  observation was refused (partial data is never presented as complete);
- an explicit `empty ≠ failed` distinction per source;
- mixed-origin input refused outright;
- KEV membership marked `unknown` when no catalogue was supplied, and flagged
  `stale` when the catalogue is old;
- EPSS unavailability surfaced as *unavailable*, never as a score of zero;
- evidence appended **before** derivation, so a later scoring bug cannot erase it.

### CISA KEV (`kev.py`)

`KevConnector` validates the whole document: a `count`/row mismatch, duplicate
CVE ids or malformed ids fail the document, because "not listed" answers derived
from a partial index would be wrong. `CachedKevCatalog` keeps the **last good
snapshot** across outages and reports staleness, so an outage degrades quality
instead of erasing knowledge.

## 9. Intelligence layer (versions → correlation → remediation)

The connectors answer "what did the provider say"; these modules answer what an
operator asks. Each keeps the package's core rule: **an honest "unknown" beats a
confident wrong answer.**

```python
from vuln_intel.assessment import AssessmentWorkflow
from vuln_intel.watchlist import Dependency, Inventory

inventory = Inventory(dependencies=(
    Dependency(ecosystem="maven", name="log4j-core", version="2.14.1", asset="payments-api"),
    Dependency(ecosystem="npm",   name="lodash",      version="4.17.21", asset="web"),
))

report = AssessmentWorkflow(
    collectors={"nvd": lambda: [nvd_record], "osv": lambda: [osv_records]},
    inventory=inventory,
).run()

report.top_risks[0].instruction
# 'emergency upgrade log4j-core to 2.15.0 — CISA remediation due 2021-12-24'
report.as_dict()["summary"]
# {'clusters': 2, 'actionable': 1, 'overdue': 1,
#  'assets_at_risk': ['payments-api'], 'incomplete': False}
```

### Affected-version evaluation (`versions.py`, `affected.py`)

Six real ordering schemes, chosen per ecosystem, with `opaque` for the ones
without a defensible ordering (rubygems, cocoapods, oss-fuzz). Comparison returns
`None` rather than guessing; the evaluator returns `UNKNOWN`, never
`NOT_AFFECTED`, when it cannot decide.

The two orderings that break naive implementations and are pinned by tests:

| Case | Rule |
|---|---|
| `1.0~rc1 < 1.0` | Debian/`dpkg`: `~` sorts before the end of the string |
| `1.0-alpha < 1.0 == 1.0.0 < 1.0.1 < 1.0-sp1` | Maven: qualifiers rank below a missing component |

### Correlation (`correlation.py`)

Twelve identifier families; records merge only on an identifier a source
actually published. Two different defects in one package stay two findings.

### Remediation (`remediation.py`)

| Action | When |
|---|---|
| `emergency_patch` | in KEV (exploited in the wild), or the CISA due date is near/past |
| `patch` | a fixed release exists |
| `upgrade_major` | the fix crosses a major boundary (flagged: test needed) |
| `mitigate` | affected, no fixed release — suggests vector-derived mitigations |
| `monitor` | not affected now, or applicability could not be determined |
| `none` | not applicable |

The target is the **lowest** published fix: advise the smallest change that
removes the risk. Upgrade cost is a stated *proxy* for bump risk, not a model.

### Incremental sync (`sync.py`)

NVD's `lastModStartDate`/`lastModEndDate` windows with a checkpoint that advances
**only over fully completed windows**. A failed page or an exhausted page budget
holds the watermark, because advancing past unfetched records loses coverage
permanently and silently.

### Operations (`config.py`, `health.py`)

`Settings.from_env()` reads ten documented variables with live collection
**off by default**; `Secret` masks itself in `repr`, `str`, `format` and
f-strings. `build_health_report()` derives `ready`/`degraded`/`not_ready` from
recorded outcomes with no I/O, so it is safe as a liveness probe.

## 10. Error handling contract

| Situation | Result |
|---|---|
| source unreachable / no transport | `SourceUnavailable` / `SourceResponseError`; `CollectionResult` → `FAILED` |
| 404 | `SourceNotFound` (a fact, not a fault) |
| 429 | `SourceRateLimited` with `retry_after`; retried when the pause is short |
| malformed envelope | error — never an empty result |
| malformed single record in a batch | record skipped, batch → `PARTIAL`, reason in `warnings` |
| credentials in an error message | redacted by `errors.sanitize` (redacts to end of line) |

## 11. Known limitations (do not overstate)

1. **No live verification.** NVD, OSV and CISA KEV are fixture-tested only; EPSS
   has no HTTP client. Endpoint shape, provider terms, API keys and real rate
   limits are unverified. `LAST_VERIFIED_LIVE` is `None` in all three connectors
   and a CI guard fails the build if that changes without evidence.
2. **No persistence.** Nothing writes to a database. Storage requirements are
   documented (`docs/vulnerability-intelligence/INTEGRATION.md`); the strategy
   decision is the owner's.
3. **No OSV batch/POST query.** Only `GET /vulns/<id>`; `query`/`querybatch` are
   POST endpoints and are unimplemented. The watchlist already builds the bodies.
4. **Rate gating is per-process**, not cluster-wide, and does not coordinate
   across workers. A breaker is per instance too.
5. **v4.0 scoring is base-quality only in one sense:** the *environmental* group
   is honoured, but this package never sets it — it carries whatever the source
   supplied. Nothing here assesses exploit maturity beyond the source's `E`.
6. **Version ordering is unavailable for some ecosystems** (rubygems,
   cocoapods, oss-fuzz). Those verdicts are `UNKNOWN` by decision, not oversight.
7. **Prioritization is decision support**, not an automated remediation
   decision: the weights are provisional and require owner sign-off.
8. **`search_all()` is a bounded window**, not a full NVD mirror.
   `IncrementalSync` is the mechanism for real coverage.
9. **KEV membership depends on catalogue freshness.** A stale cache is flagged,
   never silently treated as current.
10. **Observation log is in-memory here.** Durability, retention and tamper
    resistance are properties of the host adapter, not of this reference log.
11. **`sources.py` is not integrated** — deliberately, per the assignment rules.
12. **No API endpoints.** The package provides services, not routes; routing is
    the host application's decision.

## 12. Integration layer

`vuln_intel/integration/` defines the seam without touching the host:

- `contracts.py` — `VulnerabilityStore` and `AuditPort` protocols the host implements;
- `mapping.py` — `NormalizedVulnerability` → the host's
  `Entity(kind='vulnerability')` + `*_catalog_records.details` shape, with the
  package's own fields under `details["cicc_enrichment"]` so existing readers
  keep working;
- `service.py` — `IngestionService`: origin gate, dry-run by default, age gate,
  audit coupling, per-record outcomes (no batch-wide abort);
- `store.py` — reference in-memory store honouring the same invariants, plus
  `RefusingStore` (deny by default when no approval exists);
- `preview.py` — generates the review artifact and **exits non-zero** if a
  separation rule breaks.

Compatibility with the current repository, the database requirements (Path A:
reuse existing tables / Path B: one new table) and the credential conditions are
documented in [`docs/vulnerability-intelligence/INTEGRATION.md`](../../docs/vulnerability-intelligence/INTEGRATION.md).
A reviewer checklist lives in
[`REVIEW_CHECKLIST.md`](../../docs/vulnerability-intelligence/REVIEW_CHECKLIST.md).

**No migration is authored by this change.**

## 13. Integration checklist for the reviewer

- [ ] Confirm the target integration point (`apps/api/app/sources.py` in the
      lineage that owns it) before wiring.
- [ ] Decide the persistence mapping for `NormalizedVulnerability`
      (new table vs. reuse of an existing CVE table) — needs a migration.
- [ ] Obtain an NVD API key; then run one supervised live fetch and set
      `LAST_VERIFIED_LIVE` only if it succeeds.
- [ ] Confirm FIRST EPSS terms for the intended use before enabling a provider.
- [ ] Wire `rank_vulnerabilities` behind an authenticated, tenant-scoped endpoint
      with `PriorityContext` sourced from asset/business data.
