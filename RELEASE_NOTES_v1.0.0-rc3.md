# SecDoctor v1.0.0-rc3

## Highlights

- One-click **Export report** after a Desktop audit.
- Human-readable Markdown and machine-readable JSON (`secdoctor.report/v1`).
- Explicit provider completeness and fail-closed security status in exported evidence.
- Optional remediation-proof summary with local Ed25519 verification status and reviewed version changes.
- Privacy-conscious export: absolute project paths, session tokens, raw proof signatures/keys, command output, and test output are not exported.

## Current remediation scope

Verified Apply/Rollback remains limited to npm projects using `package-lock.json`. Other ecosystems may be detected and reported without automated remediation.

## Security boundaries

This release candidate does not claim perfect sandboxing or OS-level npm egress isolation. See `SECURITY.md` and `SECURITY-REVIEW-V1-RC.md`. Keep source control or an independent backup for important projects.
