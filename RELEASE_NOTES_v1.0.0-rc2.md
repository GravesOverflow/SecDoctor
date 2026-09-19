# SecDoctor v1.0.0-rc2

First public release candidate of SecDoctor.

## Highlights

- Local desktop security audit for dependency projects.
- npm remediation workflow: Audit → Preview → Lab → Signed Proof → Apply → Runtime Verify → Re-scan → Rollback.
- Deterministic remediation decisions and verification.
- Signed Ed25519 Lab proof bound to the remediation plan and lockfile hashes.
- Runtime verification after Apply and Rollback.
- Windows rollback recovery for transient `ENOTEMPTY`, `EPERM`, and `EBUSY` failures.
- Explicit fail-closed vulnerability-provider states.
- Loopback-only desktop API protected by a per-process session token and Origin validation.
- Optional strict Docker Lab mode with `SECDOCTOR_STRICT_LAB=1`.

## Current remediation scope

Verified Apply/Rollback remediation in this release candidate is for npm projects using `package-lock.json`.

Other supported ecosystems may be detected and reported without an automated remediation backend.

## Windows

Download `SecDoctor-windows-amd64.exe`, rename it to `SecDoctor.exe` if desired, and run it.

Windows SmartScreen may warn about an unsigned new executable. This release candidate is not code-signed.

## Verification

Every release includes `checksums.txt`.

PowerShell:

```powershell
Get-FileHash .\SecDoctor-windows-amd64.exe -Algorithm SHA256
```

Compare the result with the corresponding line in `checksums.txt`.

## Security boundaries

This release candidate does not claim perfect sandboxing or OS-level npm egress isolation. See `SECURITY.md` and `SECURITY-REVIEW-V1-RC.md` in the repository before using remediation on important projects.

Keep source control or an independent backup for important projects.
