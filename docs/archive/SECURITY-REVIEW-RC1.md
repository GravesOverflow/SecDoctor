# SecDoctor v0.9.0-rc1 — External Dependency & Trust Review

Date: 2026-09-19

## Scope

Reviewed network providers, external commands, remediation execution, proof trust, CI dependencies, project-copy boundaries, and rollback behavior.

## External systems

| Dependency | Purpose | Failure semantics | RC treatment |
|---|---|---|---|
| OSV API | Primary vulnerability intelligence | Fail closed | 429/5xx/timeouts retry; exhausted failure is PROVIDER_UNAVAILABLE |
| FIRST EPSS | Risk enrichment | Partial result | Failure cannot become VERIFIED_CLEAN |
| CISA KEV | Exploitation enrichment | Partial result | Failure cannot become VERIFIED_CLEAN |
| npm registry | Plan/install/runtime sync | Operation fails | Registry explicitly pinned; lifecycle scripts disabled for install |
| npm audit | Live cross-check only | Canary inconclusive | Removed from blocking deterministic E2E |
| Docker daemon | Preferred lab isolation | Workspace fallback | Proof records backend and assurance |
| Docker image registry | Pull node lab image | Lab can fail/fallback | Still external; image digest is not yet pinned |

## Fixed for this RC

1. Blocking E2E no longer depends on live npm/advisory infrastructure.
2. Live npm audit regression moved to a separate scheduled/manual canary.
3. Lab no longer copies `.npmrc`, `.env`, `.env.*`, `.netrc`, `.pypirc`, private-key-like `.key/.pem`, or symlinks.
4. Candidate npm lockfiles are rejected when `resolved` package URLs leave HTTPS `registry.npmjs.org`.
5. Plan generation ignores project `.npmrc`, uses an empty user config, strips credential-bearing environment variables, and pins the registry.
6. Proof verification now anchors the embedded Ed25519 public key to the local SecDoctor installation key. A replacement proof signed by an attacker-generated key is rejected.
7. Desktop Apply uses a server-side verified-proof gate. Bypassing the GUI no longer bypasses proof validation.
8. Candidate lockfile hash is rechecked at Apply.
9. Runtime-sync failure triggers automatic best-effort restoration of the original lockfile and runtime.
10. Primary-provider outage is explicitly UNKNOWN/PROVIDER_UNAVAILABLE, never clean.

## Remaining RC limitations

### High priority before v1.0

- Docker install still uses bridge networking. Registry pinning and lockfile URL validation reduce scope but are not an OS-level egress firewall.
- `node:24-alpine` is a mutable image tag. Pin a tested image digest and record it in proof metadata.
- Workspace fallback tests inherit host networking. High-assurance mode should optionally refuse fallback.
- Local Ed25519 private key is a filesystem key. On Windows, use DPAPI/CNG or equivalent protected storage for stronger key-at-rest protection.
- Automatic rollback is best effort; a second npm failure can leave runtime restoration incomplete. The error is explicit, but atomic runtime snapshots are not implemented.

### Release engineering

- Go module path is still `github.com/example/secdoctor`. Replace it with the actual public repository path before publishing source as v1.0.
- GitHub Actions are on current v7 major releases, but are not pinned to immutable full commit SHAs yet.
- The live canary intentionally depends on changing npm advisory data and may become historically stale; it is non-blocking for that reason.

### Proof/privacy

- Proof metadata contains the local project path. Add a redacted/portable export mode before encouraging users to publish proofs.
- `working_tree_untouched` currently proves the original lockfile hash is unchanged during lab verification, not a cryptographic manifest of every project file. Rename or extend this field for v1.

## RC decision

The deterministic remediation transaction is suitable for release-candidate testing. The remaining items above are documented boundaries, not claims of completed isolation. Public v1.0 should wait for repository identity, immutable CI pins, Docker image digest pinning, and a decision on strict egress isolation.
