# Three differentiating v0.4 features

## 1. Evidence Ladder
Every vulnerability shows independent signals instead of a made-up risk score:
CVSS severity, EPSS probability/percentile, CISA KEV exploitation status, direct/transitive dependency, fixed-version availability, and source freshness.

## 2. Project Impact CVE Lookup
`secdoctor cve CVE-YYYY-NNNN --project .` answers both “what is this CVE?” and “does a supported manifest show my project using an affected package/version?” in one command.

## 3. Reproducible Offline Security Snapshot
A project can be scanned using a previously populated intelligence cache with `--offline`. This is useful for restricted CI, air-gapped review, demos, and reproducible comparisons. Reports should expose cache/source freshness rather than silently presenting stale intelligence as current.
