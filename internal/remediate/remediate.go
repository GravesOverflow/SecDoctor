package remediate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"secdoctor/internal/packages"
	"secdoctor/internal/pkgmodel"
)

type Change struct {
	Package string `json:"package"`
	From    string `json:"from"`
	To      string `json:"to"`
	Direct  bool   `json:"direct"`
}

type Plan struct {
	ID         string   `json:"id"`
	Root       string   `json:"root"`
	Manager    string   `json:"manager"`
	Changes    []Change `json:"changes"`
	Files      []string `json:"files"`
	Command    string   `json:"command"`
	CreatedAt  string   `json:"created_at"`
	BaseSHA256 string   `json:"base_sha256"`
}

type RollbackResult struct {
	PlanID              string `json:"plan_id"`
	LockfileRestored    bool   `json:"lockfile_restored"`
	RuntimeWasInstalled bool   `json:"runtime_was_installed"`
	RuntimeSynced       bool   `json:"runtime_synced"`
	RuntimeStatus       string `json:"runtime_status"`
	RuntimeOutput       string `json:"runtime_output,omitempty"`
}

type ApplyResult struct {
	PlanID           string `json:"plan_id"`
	BackupPath       string `json:"backup_path"`
	Applied          bool   `json:"applied"`
	RuntimeRequested bool   `json:"runtime_requested"`
	RuntimeSynced    bool   `json:"runtime_synced"`
	RuntimeCommand   string `json:"runtime_command,omitempty"`
	RuntimeOutput    string `json:"runtime_output,omitempty"`
	RuntimeStatus    string `json:"runtime_status"`
	TestCommand      string `json:"test_command,omitempty"`
	TestsRun         bool   `json:"tests_run"`
	TestsPassed      bool   `json:"tests_passed"`
	TestOutput       string `json:"test_output,omitempty"`
}

func PlanNPM(ctx context.Context, root string, requested map[string]string) (Plan, error) {
	if _, err := exec.LookPath("npm"); err != nil {
		return Plan{}, errors.New("npm is required for npm Fix & Verify")
	}
	lock := filepath.Join(root, "package-lock.json")
	pkg := filepath.Join(root, "package.json")
	if _, err := os.Stat(lock); err != nil {
		return Plan{}, errors.New("package-lock.json is required")
	}
	if _, err := os.Stat(pkg); err != nil {
		return Plan{}, errors.New("package.json is required")
	}

	before, err := packages.Discover(root)
	if err != nil {
		return Plan{}, err
	}
	tmp, err := os.MkdirTemp("", "secdoctor-plan-*")
	if err != nil {
		return Plan{}, err
	}
	defer os.RemoveAll(tmp)
	for _, name := range []string{"package.json", "package-lock.json"} {
		src := filepath.Join(root, name)
		if _, e := os.Stat(src); e == nil {
			if e = copyFile(src, filepath.Join(tmp, name)); e != nil {
				return Plan{}, e
			}
		}
	}
	// Do not use `npm audit fix` here. Newer npm versions can emit multiple JSON
	// documents/progress records internally, which makes preview brittle and was
	// the source of the v0.4.0 "JSON.parse ... after JSON data" failure.
	// `npm install --package-lock-only` asks npm to resolve the reviewed direct
	// dependency targets while never installing packages or running lifecycle scripts.
	targets := requestedTargets(before, requested)
	if len(targets) == 0 {
		return Plan{}, errors.New("no direct npm dependencies have a safe fixed version to preview")
	}
	args := []string{"install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org"}
	args = append(args, targets...)
	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = tmp
	emptyNPMRC := filepath.Join(tmp, ".secdoctor-empty-npmrc")
	if err = os.WriteFile(emptyNPMRC, []byte{}, 0600); err != nil {
		return Plan{}, err
	}
	cmd.Env = append(safeCommandEnv(), "CI=true", "NPM_CONFIG_USERCONFIG="+emptyNPMRC, "NPM_CONFIG_REGISTRY=https://registry.npmjs.org")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return Plan{}, ctx.Err()
	}
	if err != nil {
		return Plan{}, fmt.Errorf("npm could not produce a remediation plan: %s", trimOutput(out))
	}
	after, err := packages.Discover(tmp)
	if err != nil {
		return Plan{}, err
	}
	changes := compare(before, after)
	if len(changes) == 0 {
		return Plan{}, errors.New("npm did not propose a lockfile change")
	}
	id, err := newID()
	if err != nil {
		return Plan{}, err
	}
	planDir := filepath.Join(stateDir(), "plans", id)
	if err = os.MkdirAll(planDir, 0700); err != nil {
		return Plan{}, err
	}
	if err = copyFile(filepath.Join(tmp, "package-lock.json"), filepath.Join(planDir, "package-lock.json")); err != nil {
		return Plan{}, err
	}
	baseHash, err := fileSHA256(lock)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{ID: id, Root: root, Manager: "npm", Changes: changes, Files: []string{"package-lock.json"}, Command: "npm install --package-lock-only --ignore-scripts --no-audit --no-fund <reviewed targets>", CreatedAt: time.Now().UTC().Format(time.RFC3339), BaseSHA256: baseHash}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err = os.WriteFile(filepath.Join(planDir, "plan.json"), b, 0600); err != nil {
		return Plan{}, err
	}
	return p, nil
}

func ApplyVerified(ctx context.Context, id string, syncRuntime, runTests bool) (ApplyResult, error) {
	p, err := loadPlan(id)
	if err != nil {
		return ApplyResult{}, err
	}
	proof, err := Proof(id)
	if err != nil {
		return ApplyResult{}, errors.New("verified lab proof required before apply")
	}
	if err = VerifyProofSignature(proof); err != nil {
		return ApplyResult{}, fmt.Errorf("invalid lab proof: %w", err)
	}
	if proof.PlanID != id || proof.OriginalSHA256 != p.BaseSHA256 || !proof.InstallPassed || !proof.WorkingTreeClean {
		return ApplyResult{}, errors.New("lab proof does not satisfy apply policy")
	}
	candidate := filepath.Join(stateDir(), "plans", id, "package-lock.json")
	h, err := fileSHA256(candidate)
	if err != nil {
		return ApplyResult{}, err
	}
	if h != proof.CandidateSHA256 {
		return ApplyResult{}, errors.New("candidate lockfile changed after lab verification")
	}
	return Apply(ctx, id, syncRuntime, runTests)
}

func Apply(ctx context.Context, id string, syncRuntime, runTests bool) (ApplyResult, error) {
	p, err := loadPlan(id)
	if err != nil {
		return ApplyResult{}, err
	}
	planDir := filepath.Join(stateDir(), "plans", id)
	current := filepath.Join(p.Root, "package-lock.json")
	if _, err = os.Stat(current); err != nil {
		return ApplyResult{}, err
	}
	currentHash, e := fileSHA256(current)
	if e != nil {
		return ApplyResult{}, e
	}
	if currentHash != p.BaseSHA256 {
		return ApplyResult{}, errors.New("package-lock.json changed after preview; create a new fix plan")
	}
	backup := filepath.Join(stateDir(), "backups", id)
	if err = os.MkdirAll(backup, 0700); err != nil {
		return ApplyResult{}, err
	}
	if err = copyFile(current, filepath.Join(backup, "package-lock.json")); err != nil {
		return ApplyResult{}, err
	}
	if _, statErr := os.Stat(filepath.Join(p.Root, "node_modules")); statErr == nil {
		if err = os.WriteFile(filepath.Join(backup, "runtime-installed"), []byte("true\n"), 0600); err != nil {
			return ApplyResult{}, err
		}
	}
	if err = copyFile(filepath.Join(planDir, "package-lock.json"), current); err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{PlanID: id, BackupPath: backup, Applied: true, RuntimeRequested: syncRuntime, RuntimeStatus: "not_requested"}
	if syncRuntime {
		result.RuntimeCommand = "npm ci --ignore-scripts --no-audit --no-fund"
		if _, statErr := os.Stat(filepath.Join(p.Root, "node_modules")); statErr == nil {
			// Runtime synchronization is explicit because npm ci replaces node_modules.
			cmd := exec.CommandContext(ctx, "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund")
			cmd.Dir = p.Root
			cmd.Env = append(safeCommandEnv(), "CI=true", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org")
			out, runErr := cmd.CombinedOutput()
			result.RuntimeOutput = trimOutput(out)
			result.RuntimeSynced = runErr == nil
			if runErr == nil {
				if verifyErr := verifyChangedRuntimeVersions(p.Root, p.Changes); verifyErr != nil {
					runErr = verifyErr
					result.RuntimeOutput = trimOutput([]byte(result.RuntimeOutput + "\n" + verifyErr.Error()))
					result.RuntimeSynced = false
					result.RuntimeStatus = "failed"
				} else {
					result.RuntimeStatus = "verified"
				}
			} else {
				result.RuntimeStatus = "failed"
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			if runErr != nil {
				// Transactional safety: restore the original lockfile immediately. If a runtime
				// existed before apply, best-effort restore it from the restored lockfile too.
				_ = copyFile(filepath.Join(backup, "package-lock.json"), current)
				result.Applied = false
				rb := exec.CommandContext(ctx, "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund")
				rb.Dir = p.Root
				rb.Env = append(safeCommandEnv(), "CI=true", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org")
				rbOut, rbErr := rb.CombinedOutput()
				if rbErr != nil {
					return result, fmt.Errorf("runtime synchronization failed and automatic rollback was incomplete: apply=%s rollback=%s", result.RuntimeOutput, trimOutput(rbOut))
				}
				return result, fmt.Errorf("runtime synchronization failed; original lockfile and runtime were restored: %s", result.RuntimeOutput)
			}
		} else if errors.Is(statErr, os.ErrNotExist) {
			result.RuntimeStatus = "not_installed"
		} else {
			return result, statErr
		}
	}
	if !runTests {
		return result, nil
	}
	testCmd := detectTestCommand(p.Root)
	result.TestCommand = testCmd
	if testCmd == "" {
		return result, nil
	}
	result.TestsRun = true
	cmd := exec.CommandContext(ctx, "npm", "test")
	cmd.Dir = p.Root
	cmd.Env = append(safeCommandEnv(), "CI=true", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org")
	out, e := cmd.CombinedOutput()
	result.TestOutput = trimOutput(out)
	result.TestsPassed = e == nil
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

func Rollback(ctx context.Context, id string, syncRuntime bool) (RollbackResult, error) {
	p, err := loadPlan(id)
	if err != nil {
		return RollbackResult{}, err
	}
	src := filepath.Join(stateDir(), "backups", id, "package-lock.json")
	if _, err = os.Stat(src); err != nil {
		return RollbackResult{}, errors.New("backup not found")
	}
	result := RollbackResult{PlanID: id, RuntimeStatus: "not_requested"}
	wasInstalled := false
	if _, e := os.Stat(filepath.Join(stateDir(), "backups", id, "runtime-installed")); e == nil {
		wasInstalled = true
	}
	result.RuntimeWasInstalled = wasInstalled
	if err = copyFile(src, filepath.Join(p.Root, "package-lock.json")); err != nil {
		return result, err
	}
	result.LockfileRestored = true
	if !syncRuntime {
		return result, nil
	}
	if !wasInstalled {
		result.RuntimeStatus = "not_previously_installed"
		return result, nil
	}
	result.RuntimeStatus = "syncing"
	out, e := npmCIRobust(ctx, p.Root)
	result.RuntimeOutput = trimOutput(out)
	if ctx.Err() != nil {
		result.RuntimeStatus = "failed"
		return result, ctx.Err()
	}
	if e != nil {
		result.RuntimeStatus = "failed"
		return result, fmt.Errorf("lockfile restored but runtime rollback failed: %s", result.RuntimeOutput)
	}
	if verifyErr := verifyChangedRuntimeVersionsRollback(p.Root, p.Changes); verifyErr != nil {
		result.RuntimeStatus = "failed"
		return result, verifyErr
	}
	result.RuntimeSynced = true
	result.RuntimeStatus = "verified"
	return result, nil
}

func loadPlan(id string) (Plan, error) {
	if strings.ContainsAny(id, `/\\.`) {
		return Plan{}, errors.New("invalid plan id")
	}
	b, err := os.ReadFile(filepath.Join(stateDir(), "plans", id, "plan.json"))
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if err = json.Unmarshal(b, &p); err != nil {
		return Plan{}, err
	}
	return p, nil
}
func requestedTargets(pkgs []pkgmodel.Package, requested map[string]string) []string {
	var out []string
	for _, p := range pkgs {
		if !p.Direct || !strings.EqualFold(p.Ecosystem, "npm") {
			continue
		}
		v := strings.TrimSpace(requested[p.Name])
		if v == "" {
			continue
		}
		out = append(out, p.Name+"@"+v)
	}
	sort.Strings(out)
	return out
}

func compare(before, after []pkgmodel.Package) []Change {
	bm := map[string]pkgmodel.Package{}
	am := map[string]pkgmodel.Package{}
	for _, p := range before {
		if strings.EqualFold(p.Ecosystem, "npm") {
			bm[p.Name] = p
		}
	}
	for _, p := range after {
		if strings.EqualFold(p.Ecosystem, "npm") {
			am[p.Name] = p
		}
	}
	var out []Change
	for n, b := range bm {
		if a, ok := am[n]; ok && a.Version != b.Version {
			out = append(out, Change{Package: n, From: b.Version, To: a.Version, Direct: b.Direct})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Direct != out[j].Direct {
			return out[i].Direct
		}
		return out[i].Package < out[j].Package
	})
	return out
}
func newID() (string, error) {
	b := make([]byte, 12)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func stateDir() string {
	if d, e := os.UserCacheDir(); e == nil {
		return filepath.Join(d, "SecDoctor")
	}
	return filepath.Join(os.TempDir(), "SecDoctor")
}
func copyFile(src, dst string) error {
	b, e := os.ReadFile(src)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
		return e
	}
	return os.WriteFile(dst, b, 0600)
}
func fileSHA256(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func sameFile(a, b string) bool {
	x, e := os.ReadFile(a)
	if e != nil {
		return false
	}
	y, e := os.ReadFile(b)
	return e == nil && string(x) == string(y)
}
func trimOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 4000 {
		s = s[len(s)-4000:]
	}
	return s
}
func detectTestCommand(root string) string {
	b, e := os.ReadFile(filepath.Join(root, "package.json"))
	if e != nil {
		return ""
	}
	var d struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(b, &d) != nil {
		return ""
	}
	t := strings.TrimSpace(d.Scripts["test"])
	if t == "" || strings.Contains(t, "Error: no test specified") {
		return ""
	}
	return "npm test"
}

func safeCommandEnv() []string {
	keep := map[string]bool{"PATH": true, "Path": true, "SystemRoot": true, "SYSTEMROOT": true, "COMSPEC": true, "PATHEXT": true, "TEMP": true, "TMP": true, "LANG": true, "HOME": true, "USERPROFILE": true}
	out := make([]string, 0, 16)
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if keep[k] {
			out = append(out, v)
		}
	}
	return out
}

func verifyChangedRuntimeVersions(root string, changes []Change) error {
	for _, ch := range changes {
		if !ch.Direct {
			continue
		}
		path := filepath.Join(append([]string{root, "node_modules"}, strings.Split(ch.Package, "/")...)...)
		b, err := os.ReadFile(filepath.Join(path, "package.json"))
		if err != nil {
			return fmt.Errorf("runtime verification failed for %s: %w", ch.Package, err)
		}
		var d struct {
			Version string `json:"version"`
		}
		if err = json.Unmarshal(b, &d); err != nil {
			return fmt.Errorf("runtime verification failed for %s: %w", ch.Package, err)
		}
		if d.Version != ch.To {
			return fmt.Errorf("runtime verification failed for %s: expected %s, installed %s", ch.Package, ch.To, d.Version)
		}
	}
	return nil
}

func npmCIRobust(ctx context.Context, root string) ([]byte, error) {
	run := func() ([]byte, error) {
		cmd := exec.CommandContext(ctx, "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund")
		cmd.Dir = root
		cmd.Env = append(safeCommandEnv(), "CI=true", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org")
		return cmd.CombinedOutput()
	}
	out, err := run()
	if err == nil || ctx.Err() != nil {
		return out, err
	}
	low := strings.ToLower(string(out))
	// Windows/npm can fail to remove a populated package directory with ENOTEMPTY
	// while replacing node_modules. A clean retry is deterministic and matches npm ci's
	// intended semantics: node_modules is disposable runtime state derived from lockfile.
	if !strings.Contains(low, "enotempty") && !strings.Contains(low, "eperm") && !strings.Contains(low, "ebusy") {
		return out, err
	}
	modules := filepath.Join(root, "node_modules")
	if removeErr := removeTreeWithRetry(ctx, modules); removeErr != nil {
		return append(out, []byte("\nSecDoctor cleanup failed: "+removeErr.Error())...), err
	}
	retryOut, retryErr := run()
	return append(append(out, []byte("\nSecDoctor: cleaned node_modules and retried npm ci.\n")...), retryOut...), retryErr
}
func removeTreeWithRetry(ctx context.Context, path string) error {
	var last error
	for i := 0; i < 5; i++ {
		last = os.RemoveAll(path)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(i+1) * 150 * time.Millisecond):
		}
	}
	return last
}
func verifyChangedRuntimeVersionsRollback(root string, changes []Change) error {
	for _, ch := range changes {
		if !ch.Direct {
			continue
		}
		path := filepath.Join(append([]string{root, "node_modules"}, strings.Split(ch.Package, "/")...)...)
		b, err := os.ReadFile(filepath.Join(path, "package.json"))
		if err != nil {
			return fmt.Errorf("rollback runtime verification failed for %s: %w", ch.Package, err)
		}
		var d struct {
			Version string `json:"version"`
		}
		if err = json.Unmarshal(b, &d); err != nil {
			return fmt.Errorf("rollback runtime verification failed for %s: %w", ch.Package, err)
		}
		if d.Version != ch.From {
			return fmt.Errorf("rollback runtime verification failed for %s: expected %s, installed %s", ch.Package, ch.From, d.Version)
		}
	}
	return nil
}
