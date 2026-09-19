# SecDoctor v1.0.0-rc1 Security Review

## Closed blockers

- Deterministic blocking E2E is independent of npm audit and public advisory infrastructure.
- Live npm ecosystem checks are separate canaries.
- Primary provider outages fail closed and cannot be presented as a clean audit.
- Remediation Lab excludes `.npmrc`, `.env*`, `.netrc`, `.pypirc`, key-like files and symlinks.
- Candidate npm lockfiles reject package `resolved` URLs outside HTTPS `registry.npmjs.org`.
- Plan/install commands strip credential-bearing environment variables and disable lifecycle scripts during install.
- Apply requires a locally trusted Ed25519 signed proof on the server side, not only in the GUI.
- Apply revalidates original and candidate lockfile hashes.
- Runtime sync independently checks installed direct dependency versions.
- Runtime-sync failure automatically attempts restoration of the original lockfile and runtime.
- Desktop API binds to loopback only and now requires a random per-process 256-bit session token for every `/api/` request.
- Desktop rejects foreign browser Origins for API calls.
- Strict high-assurance mode (`SECDOCTOR_STRICT_LAB=1`) refuses workspace fallback when Docker is unavailable.
- Lab proof records the exact configured container image reference.
- Module path no longer uses the `github.com/example/...` placeholder.

## Deliberately documented boundaries

### Network isolation

The Docker install phase still needs package-registry access. SecDoctor restricts npm configuration and lockfile resolved hosts, but Docker bridge networking is not an OS-level destination allowlist. Lifecycle scripts are disabled during install, reducing package-code execution. Tests run with `--network none` in Docker.

For environments requiring a hard egress boundary, run the registry behind an organization-controlled proxy/firewall and set the approved container/network policy externally.

### Container image

Default image is `node:24.9.0-alpine3.22`. Production operators can pin an immutable digest through `SECDOCTOR_NODE_IMAGE`. The proof records the resulting image reference. The release does not claim a universal Docker Hub digest because digest availability is platform/manifest specific and must be verified in the deployment environment.

### Signing key at rest

The local Ed25519 proof key is stored under the SecDoctor user cache with restrictive file permissions where supported. It is a local integrity/trust anchor, not publisher identity or hardware-backed attestation. OS-native key protection remains a future hardening option.

### Rollback

Rollback is transactional on the lockfile and best-effort for `node_modules`. If npm itself fails during restoration, SecDoctor reports rollback as incomplete rather than claiming success.

### Workspace fallback

Workspace fallback remains available for usability and is explicitly lower assurance. Set `SECDOCTOR_STRICT_LAB=1` to require Docker and refuse fallback.

## v1 RC security posture

The release candidate is suitable for external testing with the boundaries above stated explicitly. It does not claim perfect sandboxing, complete egress isolation, or publisher-signed attestations.
