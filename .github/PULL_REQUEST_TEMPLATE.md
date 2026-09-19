## What changed

Describe the change and the security/remediation behavior it affects.

## Verification

- [ ] `go test -count=1 ./...`
- [ ] `go test -race -count=1 ./...`
- [ ] `go vet ./...`
- [ ] `go run ./cmd/secdoctor-e2e`
- [ ] No secrets, credentials, generated binaries, or private project data are included
