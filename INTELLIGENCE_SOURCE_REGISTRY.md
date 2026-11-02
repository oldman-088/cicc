# Intelligence source registry

| Source | Status | Last attempt | Last success | Notes |
|---|---|---|---|---|
| CISA KEV | IN_PROGRESS | never | never | Fixed-URL fetch, internal tenant-scoped import and sync coordinator tested with synthetic fixtures; no scheduled or live-verified sync |
| NIST NVD | IN_PROGRESS | never | never | Single-CVE fixed-URL adapter and internal tenant-scoped importer tested only with synthetic fixtures; no exposed read/sync API, scheduler, shared rate limiting or live verification; provider policy unverified |
| MITRE ATT&CK | NOT_STARTED | never | never | Planned; distribution/versioning need validation |
| Synthetic exercise | TESTED | n/a | n/a | Hardcoded illustrative examples, not real intelligence |

No source connections are operational. Additional user-listed sources remain candidates, not approved or integrated.

Internal sync coordinator tracks running/succeeded/failed/abandoned attempts and imported snapshot metadata, but has no scheduler, start-sync API or UI integration; an experimental admin status/recovery API exists. It has not been run against CISA. A crash may leave a running attempt requiring explicit operator abandonment. No live requests have been attempted in this environment. Provider terms, real schema and access must be verified before enabling operational use.
