package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"secdoctor/internal/remediate"
)

const oldVersion = "4.17.20"
const newVersion = "4.18.0"

func main() {
	if isNPMShim() {
		os.Exit(fakeNPM(os.Args[1:]))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", "secdoctor-deterministic-e2e-*")
	must(err)
	defer os.RemoveAll(root)
	shimDir := filepath.Join(root, "bin")
	must(os.MkdirAll(shimDir, 0700))
	must(installShim(shimDir))
	oldPath := os.Getenv("PATH")
	must(os.Setenv("PATH", shimDir))
	defer os.Setenv("PATH", oldPath)

	must(writeFixture(root, oldVersion))
	must(syncRuntimeFixture(root))
	before := fixtureAdvisories(root)
	assert(before == 5, "expected fixture advisories=5, got %d", before)
	assert(runtimeVersion(root) == oldVersion, "expected runtime %s", oldVersion)
	fmt.Printf("BEFORE    advisories=%d runtime=%s source=fixture\n", before, oldVersion)

	plan, err := remediate.PlanNPM(ctx, root, map[string]string{"lodash": newVersion})
	must(err)
	proof, err := remediate.VerifyLab(ctx, plan.ID, false)
	must(err)
	must(remediate.VerifyProofSignature(proof))
	assert(proof.InstallPassed && proof.WorkingTreeClean, "lab proof gate failed")
	fmt.Printf("LAB       backend=%s signed=%t untouched=%t network=offline-shim\n", proof.Backend, proof.Signature != "", proof.WorkingTreeClean)

	applied, err := remediate.ApplyVerified(ctx, plan.ID, true, false)
	must(err)
	assert(applied.RuntimeSynced, "runtime did not synchronize")
	after := fixtureAdvisories(root)
	assert(after == 0 && runtimeVersion(root) == newVersion, "apply verification failed: advisories=%d runtime=%s", after, runtimeVersion(root))
	fmt.Printf("APPLY     advisories=%d runtime=%s\n", after, newVersion)

	rb, err := remediate.Rollback(ctx, plan.ID, true)
	must(err)
	assert(rb.LockfileRestored && rb.RuntimeSynced, "rollback did not restore lockfile/runtime")
	restored := fixtureAdvisories(root)
	assert(restored == 5 && runtimeVersion(root) == oldVersion, "rollback verification failed: advisories=%d runtime=%s", restored, runtimeVersion(root))
	fmt.Printf("ROLLBACK  advisories=%d runtime=%s\n", restored, oldVersion)
	fmt.Println("DETERMINISTIC E2E PASS: 5 -> signed lab proof -> 0 -> rollback -> 5")
}

func isNPMShim() bool {
	b := strings.ToLower(filepath.Base(os.Args[0]))
	return b == "npm" || b == "npm.exe"
}
func installShim(dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	name := "npm"
	if runtime.GOOS == "windows" {
		name = "npm.exe"
	}
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	if _, err = io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}
func fakeNPM(args []string) int {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(args) == 0 {
		return 0
	}
	switch args[0] {
	case "install":
		if contains(args, "--package-lock-only") {
			if err := setLockVersion(cwd, newVersion); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Println("SecDoctor deterministic npm shim: lockfile resolved")
			return 0
		}
	case "ci":
		if err := syncRuntimeFixture(cwd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("SecDoctor deterministic npm shim: runtime synchronized")
		return 0
	case "test":
		fmt.Println("SecDoctor deterministic npm shim: tests passed")
		return 0
	}
	fmt.Fprintf(os.Stderr, "unsupported deterministic npm invocation: %s\n", strings.Join(args, " "))
	return 2
}
func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
func writeFixture(root, version string) error {
	pkg := fmt.Sprintf(`{"name":"secdoctor-e2e-fixture","private":true,"dependencies":{"lodash":"%s"}}`, version)
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(pkg), 0600); err != nil {
		return err
	}
	if err := setLockVersion(root, version); err != nil {
		return err
	}
	return syncRuntimeFixture(root)
}
func setLockVersion(root, version string) error {
	lock := map[string]any{"name": "secdoctor-e2e-fixture", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": version}},
			"node_modules/lodash": map[string]any{"version": version, "resolved": "https://registry.npmjs.org/lodash/-/lodash-" + version + ".tgz", "integrity": "sha512-secdoctor-deterministic-fixture"},
		}}
	b, _ := json.MarshalIndent(lock, "", "  ")
	return os.WriteFile(filepath.Join(root, "package-lock.json"), b, 0600)
}
func syncRuntimeFixture(root string) error {
	var d struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	b, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &d); err != nil {
		return err
	}
	v := d.Packages["node_modules/lodash"].Version
	dir := filepath.Join(root, "node_modules", "lodash")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "package.json"), []byte(fmt.Sprintf(`{"name":"lodash","version":%q}`, v)), 0600)
}
func runtimeVersion(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "node_modules", "lodash", "package.json"))
	must(err)
	var d struct {
		Version string `json:"version"`
	}
	must(json.Unmarshal(b, &d))
	return d.Version
}
func fixtureAdvisories(root string) int {
	if runtimeVersion(root) == oldVersion {
		return 5
	}
	return 0
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "DETERMINISTIC E2E FAIL:", err)
		os.Exit(1)
	}
}
func assert(ok bool, f string, a ...any) {
	if !ok {
		fmt.Fprintf(os.Stderr, "DETERMINISTIC E2E FAIL: "+f+"\n", a...)
		os.Exit(1)
	}
}
