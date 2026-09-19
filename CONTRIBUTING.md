# Contributing

Run the quality gates before submitting a change:

```bash
go fmt ./...
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

Security-provider facts and remediation decisions must remain deterministic. AI features may explain findings but must not invent CVEs, severities, exploitation status, fixed versions, or successful verification.

New remediation backends must implement preview, explicit approval, stale-plan protection, backup, verification, and rollback before they are exposed in the UI.
