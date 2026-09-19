# SecDoctor v0.4 Test Strategy

## Unit tests
- PURL normalization for npm scoped packages, PyPI, Go, Cargo, Composer, NuGet, RubyGems.
- Every lockfile parser: valid fixture, malformed file, empty file, duplicate dependency, exact vs ranged versions.
- Cache: hit, miss, expiry, offline stale reads, atomic overwrite, clear, corrupt entry.
- Intelligence merge/sort: KEV before EPSS before CVSS, direct before transitive.
- SBOM: deterministic component mapping, valid required CycloneDX fields, round-trip read/write.

## Provider contract tests
Use httptest.Server; never depend on live services in CI.
- OSV querybatch: 200, empty results, multiple advisories, timeout, 429/500, malformed JSON.
- OSV CVE lookup: aliases, fixed versions, CVSS vector presence.
- EPSS: multi-CVE response, absent CVE, decimal parsing, timeout.
- CISA KEV: known CVE, absent CVE, ransomware field, catalog refresh.

## Offline integration
1. Prime cache using mocked providers.
2. Disable network.
3. Run scan with offline=true.
4. Assert same vulnerability IDs, EPSS, KEV and advisory metadata.
5. Expire cache timestamps and assert offline still reads stale data.
6. Assert uncached offline query returns a clear warning/error without a network attempt.

## SBOM integration
- mixed monorepo fixture with npm + PyPI + Go.
- generate bom.cdx.json.
- assert unique components and PURLs.
- parse generated SBOM back into package inventory.
- malformed SBOM must fail safely.

## CLI acceptance
- `secdoctor .`
- `secdoctor scan --offline .`
- `secdoctor cve CVE-...`
- `secdoctor cve CVE-... --project .`
- `secdoctor sbom . -o bom.cdx.json`
- `secdoctor cache status`
- `secdoctor cache clear`
- `secdoctor doctor`
- `secdoctor --json .`

## Security/regression
- never print matched secret values.
- path traversal cannot escape cache directory.
- cache files mode 0600.
- HTTP bodies bounded where practical.
- provider outage never disables deterministic local checks.
- ranged dependency versions are never guessed.
- duplicate packages do not multiply findings.

## Release matrix
- linux/amd64, linux/arm64
- darwin/amd64, darwin/arm64
- windows/amd64, windows/arm64
- `go test ./...`
- `go vet ./...`
- smoke-test built binary with `version`, `doctor`, and a fixture scan.
