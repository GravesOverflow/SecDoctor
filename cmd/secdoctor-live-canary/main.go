package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"secdoctor/internal/remediate"
)

type auditJSON struct {
	Metadata struct {
		Vulnerabilities struct {
			Total int `json:"total"`
		} `json:"vulnerabilities"`
	} `json:"metadata"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", "secdoctor-e2e-*")
	must(err)
	defer os.RemoveAll(root)
	run(ctx, root, "npm", "init", "-y")
	run(ctx, root, "npm", "install", "lodash@4.17.20", "--ignore-scripts", "--no-fund")
	before, err := auditCount(ctx, root)
	if err != nil {
		infra("%v", err)
	}
	if before != 5 {
		fatal("expected exactly 5 npm advisories before remediation, got %d", before)
	}
	v0 := runtimeVersion(ctx, root)
	if v0 != "4.17.20" {
		fatal("expected runtime 4.17.20, got %s", v0)
	}
	fmt.Printf("BEFORE  advisories=%d runtime=%s\n", before, v0)

	plan, err := remediate.PlanNPM(ctx, root, map[string]string{"lodash": "4.18.0"})
	must(err)
	proof, err := remediate.VerifyLab(ctx, plan.ID, false)
	must(err)
	must(remediate.VerifyProofSignature(proof))
	if !proof.InstallPassed || !proof.WorkingTreeClean {
		fatal("lab proof did not satisfy apply gate")
	}
	fmt.Printf("LAB     backend=%s signed=%t untouched=%t\n", proof.Backend, proof.Signature != "", proof.WorkingTreeClean)

	applied, err := remediate.ApplyVerified(ctx, plan.ID, true, false)
	must(err)
	if !applied.RuntimeSynced {
		fatal("runtime was not synchronized after apply")
	}
	after, err := auditCount(ctx, root)
	if err != nil {
		infra("%v", err)
	}
	v1 := runtimeVersion(ctx, root)
	if after != 0 || v1 != "4.18.0" {
		fatal("apply verification failed: advisories=%d runtime=%s", after, v1)
	}
	fmt.Printf("APPLY   advisories=%d runtime=%s\n", after, v1)

	rb, err := remediate.Rollback(ctx, plan.ID, true)
	must(err)
	if !rb.LockfileRestored || !rb.RuntimeSynced {
		fatal("rollback did not restore lockfile/runtime")
	}
	restored, err := auditCount(ctx, root)
	if err != nil {
		infra("%v", err)
	}
	v2 := runtimeVersion(ctx, root)
	if restored != 5 || v2 != "4.17.20" {
		fatal("rollback verification failed: advisories=%d runtime=%s", restored, v2)
	}
	fmt.Printf("ROLLBACK advisories=%d runtime=%s\n", restored, v2)
	fmt.Println("LIVE CANARY PASS: 5 -> signed lab proof -> 0 -> rollback -> 5")
}
func run(ctx context.Context, dir, name string, args ...string) string {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "CI=true")
	o, e := c.CombinedOutput()
	if e != nil {
		fatal("%s %s failed: %s", name, strings.Join(args, " "), strings.TrimSpace(string(o)))
	}
	return string(o)
}
func auditCount(ctx context.Context, dir string) (int, error) {
	var last string
	for attempt := 1; attempt <= 4; attempt++ {
		c := exec.CommandContext(ctx, "npm", "audit", "--json")
		c.Dir = dir
		o, e := c.CombinedOutput()
		raw := strings.TrimSpace(string(o))
		last = raw
		var a auditJSON
		if json.Unmarshal(o, &a) == nil {
			return a.Metadata.Vulnerabilities.Total, nil
		}
		if !isTransientAuditFailure(raw) {
			return 0, fmt.Errorf("npm audit returned invalid JSON: %s", raw)
		}
		if attempt < 4 {
			wait := time.Duration(1<<(attempt-1)) * time.Second
			fmt.Fprintf(os.Stderr, "INFRA: npm audit unavailable; retry %d/4 in %s\n", attempt, wait)
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(wait):
			}
		}
		_ = e
	}
	return 0, fmt.Errorf("npm advisory service unavailable after 4 attempts: %s", last)
}
func isTransientAuditFailure(s string) bool {
	x := strings.ToLower(s)
	for _, token := range []string{" 429 ", " 500 ", " 502 ", " 503 ", " 504 ", "service unavailable", "maintenance", "econnreset", "etimedout", "timeout"} {
		if strings.Contains(x, token) {
			return true
		}
	}
	return false
}

func runtimeVersion(ctx context.Context, dir string) string {
	return strings.TrimSpace(run(ctx, dir, "node", "-p", "require('./node_modules/lodash/package.json').version"))
}
func must(e error) {
	if e != nil {
		fatal("%v", e)
	}
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, "LIVE CANARY FAIL: "+f+"\n", a...); os.Exit(1) }
func infra(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "LIVE CANARY INCONCLUSIVE: external infrastructure unavailable: "+f+"\n", a...)
	os.Exit(2)
}
func init() { _ = filepath.Separator }
