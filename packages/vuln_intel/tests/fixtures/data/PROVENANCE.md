# Test fixture provenance

## `ctid_kev_mapping_sample.json`

**Real data, not synthetic.** This is a 10-object excerpt of the MITRE Center for
Threat-Informed Defense "Prioritize Known Exploited Vulnerabilities" mapping,
taken verbatim from:

```
center-for-threat-informed-defense/mappings-explorer
  mappings/kev/attack-16.1/kev-07.28.2025/enterprise/
  kev-07.28.2025_attack-16.1-enterprise.json
```

Source dataset: 1,183 mapping objects covering 419 CVEs, ATT&CK v16.1, mapping
framework version 07/28/2025. The excerpt keeps three CVEs
(`CVE-2019-13608`, `CVE-2024-34102`, `CVE-2024-4671`) chosen because between them
they exercise all three mapping types (`exploitation_technique`,
`primary_impact`, `secondary_impact`) and one CVE with several techniques.

**Why real data is acceptable here, and where the line is:** this fixture is a
third-party *mapping table*, not vulnerability intelligence about a live system. It
carries no claim about any asset, and it is attributed. The distinction matters —
`assert_persistable` refuses fixture-origin *records* because presenting them as
live intelligence would be a lie; a mapping table asserts nothing about
exploitation status, so using the real one makes the test stronger, not weaker.

Licence: the CTID Mappings Explorer data is published by MITRE for public use with
attribution. Any redistribution must credit the Center for Threat-Informed Defense.

Everything else in `tests/fixtures/` is synthetic and is labelled as such.
