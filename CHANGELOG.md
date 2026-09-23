# Changelog

## 1.0.0-rc3
- Added one-click Security Report export from the Desktop UI.
- Added `secdoctor.report/v1` JSON output plus a human-readable Markdown report.
- Reports preserve fail-closed provider status and audit coverage instead of presenting incomplete intelligence as clean.
- Added optional locally verified Lab-proof summary and reviewed dependency changes.
- Report exports redact absolute project paths and omit session tokens, proof key/signature material, command output, and test output.
- Added report rendering, redaction, severity-summary, and safe-filename regression tests.

## 1.0.0-rc2
- Fixed Windows rollback failures caused by npm `ENOTEMPTY`/`EPERM`/`EBUSY` while replacing `node_modules`.
- On those transient filesystem failures, SecDoctor removes disposable `node_modules` with bounded retries and reruns `npm ci` from the restored lockfile.
- Rollback now independently verifies restored direct dependency versions before reporting runtime verification success.


## 1.0.0-rc1
- Added loopback API session authentication and Origin enforcement.
- Added strict Docker-only Lab policy mode.
- Added configurable/digest-capable container image reference recorded in proof.
- Added independent installed-version runtime verification.
- Replaced placeholder Go module path.
- Completed v1 RC security review and documented remaining trust boundaries.


## 0.9.0-rc1
- Split deterministic blocking remediation E2E from live ecosystem canary.
- Added local offline npm test shim for reproducible 5 -> 0 -> rollback -> 5 regression.
- Added trusted local proof-key anchoring and server-side proof gate for Apply.
- Excluded common credential files and symlinks from lab copies.
- Added npm lockfile resolved-host policy and sanitized plan environment.
- Added automatic best-effort rollback after runtime-sync failure.
- Added external dependency and trust-boundary review.


## 0.8.1
- Added bounded retry/backoff for transient OSV 429/5xx and transport failures.
- Added fail-closed audit states: VERIFIED_CLEAN, VULNERABILITIES_FOUND, PARTIAL_RESULTS, PROVIDER_UNAVAILABLE.
- Desktop no longer presents primary-provider outages as a clean dependency scan.
- E2E now retries transient npm audit failures and reports `E2E INCONCLUSIVE` with exit code 2 for external infrastructure outages.
- Added regression tests for 429, 500, 502, 503, 504, recovery-after-retry and timeout behavior.


## 0.8.0
- Added `secdoctor.proof/v3` with persistent local Ed25519 signing.
- Proof API cryptographically verifies content before returning verified status.
- Pinned npm remediation installs to the public npm registry and kept lifecycle scripts disabled.
- Docker test phase remains fully network-disabled.
- Added live `cmd/secdoctor-e2e` regression: lodash 4.17.20 / 5 advisories → signed Lab → 4.18.0 / 0 → rollback → 4.17.20 / 5.
- Added GitHub Actions push/manual/weekly E2E workflow.
- Added signature-tamper and registry-policy unit tests.


## 0.7.0
- Added automatic hardened Docker lab backend.
- Container tests run with network disabled.
- Dropped Linux capabilities, enabled no-new-privileges, and added PID/CPU/memory limits.
- Added explicit workspace fallback with lower assurance when Docker is unavailable.
- Upgraded proof schema to `secdoctor.proof/v2` with backend, assurance and network policy.
- Added transactional runtime rollback: restored lockfile can now re-synchronize `node_modules`.
- GUI exposes the actual isolation backend instead of presenting all lab runs as equivalent.


## 0.6.0
- Added Isolated Remediation Lab before Apply.
- Apply stays disabled until lab verification succeeds.
- Added `secdoctor.proof/v1` evidence bundles with SHA-256 identity.
- Lab strips common credential-bearing environment variables and disables npm lifecycle scripts.
- Original package-lock.json is hashed before and after lab execution.
- Added explicit product boundary: workspace isolation is not a container/OS sandbox.


## 0.5.0
- Split Fix & Verify into lockfile verification and installed-runtime verification.
- Added explicit npm runtime synchronization with `npm ci --ignore-scripts --no-audit --no-fund` when `node_modules` exists.
- Added runtime verification states: verified, not installed, not requested, failed.
- GUI no longer implies the installed application is fixed when only the lockfile was verified.
- Rollback semantics explicitly state that node_modules is not reconstructed.


## 0.4.1
- Fixed Windows Preview Fix failure caused by brittle npm audit-fix output handling.
- Fix plans now use fixed-version targets already returned by the audited OSV advisories.
- Preview resolves the candidate lockfile with `npm install --package-lock-only --ignore-scripts --no-audit --no-fund` in a temporary directory.
- Automatic remediation remains limited to direct npm dependencies; transitive-only changes are never guessed.


## 0.4.0

- Added npm Fix & Verify preview workflow.
- Added lockfile SHA-256 stale-plan protection.
- Added private lockfile snapshots and rollback.
- Added optional project test execution.
- Added deterministic post-fix full-audit verification.
- Added before/after vulnerability result in the Desktop UI.
- Added remediation architecture and contribution/security documentation.

## 0.3.0

- Unified Desktop full audit: files, dependency discovery, OSV, EPSS and CISA KEV.
- Added vulnerability dashboard with CVE/GHSA, CVSS, EPSS, KEV and fixed-version context.
