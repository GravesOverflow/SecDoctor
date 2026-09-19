# Fix & Verify

SecDoctor separates **dependency-graph verification** from **installed-runtime verification**.

## Workflow

1. Audit the project and identify known dependency advisories.
2. Build a lockfile-only remediation preview in a temporary directory.
3. Show every proposed version change.
4. On approval, reject stale plans by SHA-256 and back up `package-lock.json`.
5. Apply the reviewed lockfile.
6. If `node_modules` exists and runtime synchronization is enabled, run:
   `npm ci --ignore-scripts --no-audit --no-fund`
7. Optionally run the project's real `npm test` script.
8. Re-run the full SecDoctor audit.
9. Report the two verification scopes separately:
   - Lockfile/dependency graph: verified by the post-change audit.
   - Installed runtime: verified only when npm successfully synchronized `node_modules`.
10. Keep or roll back the lockfile.

## Safety semantics

SecDoctor must never display "installed runtime verified" merely because a lockfile is clean.
`npm ci` replaces `node_modules`, so runtime synchronization is explicit in the UI.
Lifecycle scripts are disabled during automatic remediation and runtime synchronization.
Some projects require lifecycle scripts to build native/generated artifacts; users must run their normal trusted build workflow separately when required.
Rollback restores the lockfile snapshot. It does not reconstruct a previous `node_modules` directory.
