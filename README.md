# SecDoctor

**Find it. Fix it. Prove it.**

SecDoctor is a local-first dependency security remediation tool. It audits a project, previews an npm dependency fix, verifies the candidate in an isolated Lab, signs the verification proof, applies the reviewed lockfile, verifies the installed runtime, and can roll the project back.

> Current release candidate: **v1.0.0-rc3**

## What makes it useful

Most dependency scanners stop after telling you that a package is vulnerable. SecDoctor focuses on the remediation transaction:

**Audit → Preview → Lab → Signed Proof → Apply → Runtime Verify → Re-scan → Rollback**

The security decision path is deterministic. Vulnerability IDs, versions, provider results, hashes, proof verification, and runtime verification are not delegated to AI.

## Desktop app

The normal user-facing release contains only:

```text
SecDoctor.exe
README.md
LICENSE
SECURITY.md
```

Run `SecDoctor.exe`, select a local project, and use **Full Audit**.

The desktop server binds only to loopback. API requests require a random per-process session token and reject foreign browser Origins.

## Security report export

After a completed audit, **Export report** generates both a human-readable Markdown report and a machine-readable JSON report (`secdoctor.report/v1`). Reports include provider completeness, severity counts, vulnerability details, local findings, audit coverage, and—when available—a locally verified remediation-proof summary.

Exports intentionally use only the project directory name rather than its absolute path and do not include the proof private key, session token, raw signature, public key, command output, or test output.

## Supported remediation

The v1 release candidate supports verified remediation for **npm projects using `package-lock.json`**.

Detection and reporting cover additional package ecosystems, but they do not all have an Apply/Rollback backend yet. SecDoctor does not pretend otherwise.

## Verification Lab

When Docker is available, Lab verification uses a disposable Node container with:

- all Linux capabilities dropped;
- `no-new-privileges`;
- PID, CPU, and memory limits;
- lifecycle scripts disabled during install;
- credential-bearing files and environment variables excluded;
- tests executed with `--network none`.

Without Docker, SecDoctor labels its temporary-workspace fallback as lower assurance.

To require Docker and refuse fallback:

```powershell
$env:SECDOCTOR_STRICT_LAB="1"
.\SecDoctor.exe
```

`SECDOCTOR_NODE_IMAGE` can be set to an organization-approved immutable image reference. The selected image reference is recorded in the signed proof.

## Signed proof

Lab proof schema `secdoctor.proof/v3` is signed with Ed25519. Apply requires a proof signed by the local SecDoctor installation key and bound to the same plan, original lockfile hash, and candidate lockfile hash.

This is a **local integrity proof**, not publisher identity or third-party attestation.

## Provider failure semantics

SecDoctor does not turn an unavailable vulnerability provider into a clean result.

- `VERIFIED_CLEAN` — primary provider completed and returned no known vulnerabilities.
- `VULNERABILITIES_FOUND` — known vulnerabilities were returned.
- `PARTIAL_RESULTS` — available findings are shown but enrichment is incomplete.
- `PROVIDER_UNAVAILABLE` — dependency safety is unknown because the primary provider failed.

## Build from source

Requirements: Go 1.22+.

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go build -trimpath -o SecDoctor ./cmd/secdoctor-desktop
```

The deterministic remediation regression is:

```bash
go run ./cmd/secdoctor-e2e
```

It is intentionally independent of public npm/advisory infrastructure. The separate `cmd/secdoctor-live-canary` executable is for maintainers and CI, not end users.

## Security boundaries

SecDoctor is designed to reduce remediation risk, not to claim a perfect sandbox.

During Docker Lab installation, registry configuration and lockfile URLs are constrained to the npm registry, but bridge networking is not an OS-level destination firewall. Runtime rollback is best-effort if npm or the local filesystem itself fails. See `SECURITY.md` and `SECURITY-REVIEW-V1-RC.md`.

## License

MIT.
