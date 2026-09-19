package remediate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type LabProof struct {
	Schema             string   `json:"schema"`
	PlanID             string   `json:"plan_id"`
	Project            string   `json:"project"`
	CreatedAt          string   `json:"created_at"`
	Backend            string   `json:"backend"`
	Assurance          string   `json:"assurance"`
	Isolation          string   `json:"isolation"`
	NetworkPolicy      string   `json:"network_policy"`
	ContainerImage     string   `json:"container_image,omitempty"`
	Changes            []Change `json:"changes"`
	Commands           []string `json:"commands"`
	InstallPassed      bool     `json:"install_passed"`
	TestsAvailable     bool     `json:"tests_available"`
	TestsRun           bool     `json:"tests_run"`
	TestsPassed        bool     `json:"tests_passed"`
	TestOutput         string   `json:"test_output,omitempty"`
	CandidateSHA256    string   `json:"candidate_lock_sha256"`
	OriginalSHA256     string   `json:"original_lock_sha256"`
	WorkingTreeClean   bool     `json:"working_tree_untouched"`
	ProofSHA256        string   `json:"proof_sha256"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	Signature          string   `json:"signature"`
	PublicKey          string   `json:"public_key"`
}

func VerifyLab(ctx context.Context, id string, runTests bool) (LabProof, error) {
	p, err := loadPlan(id)
	if err != nil {
		return LabProof{}, err
	}
	current := filepath.Join(p.Root, "package-lock.json")
	h, err := fileSHA256(current)
	if err != nil {
		return LabProof{}, err
	}
	if h != p.BaseSHA256 {
		return LabProof{}, errors.New("project changed after preview; create a new plan")
	}
	lab, err := os.MkdirTemp("", "secdoctor-lab-*")
	if err != nil {
		return LabProof{}, err
	}
	defer os.RemoveAll(lab)
	if err = copyProjectForLab(p.Root, lab); err != nil {
		return LabProof{}, err
	}
	if err = copyFile(filepath.Join(stateDir(), "plans", id, "package-lock.json"), filepath.Join(lab, "package-lock.json")); err != nil {
		return LabProof{}, err
	}

	proof := LabProof{Schema: "secdoctor.proof/v3", PlanID: id, Project: p.Root, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Changes: p.Changes, OriginalSHA256: p.BaseSHA256, WorkingTreeClean: true}
	proof.CandidateSHA256, _ = fileSHA256(filepath.Join(lab, "package-lock.json"))
	if err = validateNPMResolvedSources(filepath.Join(lab, "package-lock.json")); err != nil {
		proof.Backend = "policy"
		proof.Assurance = "blocked"
		proof.NetworkPolicy = "candidate lockfile rejected before execution"
		return finishProof(id, current, p, proof, err)
	}
	testAvailable := detectTestCommand(lab) != ""
	proof.TestsAvailable = testAvailable

	if dockerAvailable(ctx) {
		proof.Backend = "docker"
		proof.ContainerImage = dockerImage()
		proof.Assurance = "hardened-container"
		proof.Isolation = "ephemeral Docker container; cap-drop=ALL; no-new-privileges; PID/CPU/memory limits; credentials not forwarded"
		proof.NetworkPolicy = "install: npm registry pinned to https://registry.npmjs.org with lifecycle scripts disabled; tests: network=none"
		if err = runDockerInstall(ctx, lab, &proof); err != nil {
			return finishProof(id, current, p, proof, err)
		}
		if runTests && testAvailable {
			if err = runDockerTests(ctx, lab, &proof); err != nil {
				return finishProof(id, current, p, proof, nil)
			}
		}
	} else {
		if strictLabRequired() {
			proof.Backend = "blocked"
			proof.Assurance = "strict-container-required"
			proof.NetworkPolicy = "workspace fallback disabled by SECDOCTOR_STRICT_LAB=1"
			return finishProof(id, current, p, proof, errors.New("Docker is required by strict lab policy"))
		}
		proof.Backend = "workspace"
		proof.Assurance = "process-isolation"
		proof.Isolation = "temporary workspace; .git/node_modules/generated artifacts excluded; credential-bearing environment variables stripped"
		proof.NetworkPolicy = "install: npm registry pinned to https://registry.npmjs.org; host networking remains available in fallback; tests inherit host networking"
		if err = runWorkspaceInstall(ctx, lab, &proof); err != nil {
			return finishProof(id, current, p, proof, err)
		}
		if runTests && testAvailable {
			runWorkspaceTests(ctx, lab, &proof)
		}
	}
	return finishProof(id, current, p, proof, nil)
}

func dockerAvailable(ctx context.Context) bool {
	if _, e := exec.LookPath("docker"); e != nil {
		return false
	}
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return exec.CommandContext(c, "docker", "info", "--format", "{{.ServerVersion}}").Run() == nil
}
func dockerMountPath(p string) string {
	p = filepath.ToSlash(p)
	if runtime.GOOS == "windows" && len(p) > 2 && p[1] == ':' {
		p = "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}
func dockerImage() string {
	if v := strings.TrimSpace(os.Getenv("SECDOCTOR_NODE_IMAGE")); v != "" {
		return v
	}
	return "node:24.9.0-alpine3.22"
}
func strictLabRequired() bool { return os.Getenv("SECDOCTOR_STRICT_LAB") == "1" }
func dockerBase(lab string, network string) []string {
	return []string{"run", "--rm", "--init", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--pids-limit", "256", "--memory", "1g", "--cpus", "2", "--network", network,
		"-e", "CI=true", "-e", "NPM_CONFIG_IGNORE_SCRIPTS=true", "-e", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org",
		"-v", dockerMountPath(lab) + ":/workspace", "-w", "/workspace", dockerImage()}
}
func runDockerInstall(ctx context.Context, lab string, p *LabProof) error {
	p.Commands = append(p.Commands, "docker: npm ci --ignore-scripts --no-audit --no-fund")
	args := append(dockerBase(lab, "bridge"), "npm", "ci", "--registry=https://registry.npmjs.org", "--ignore-scripts", "--no-audit", "--no-fund")
	o, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	p.InstallPassed = e == nil
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e != nil {
		return errors.New("containerized install failed: " + trimOutput(o))
	}
	return nil
}
func runDockerTests(ctx context.Context, lab string, p *LabProof) error {
	p.TestsRun = true
	p.Commands = append(p.Commands, "docker --network none: npm test")
	args := append(dockerBase(lab, "none"), "npm", "test")
	o, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	p.TestOutput = trimOutput(o)
	p.TestsPassed = e == nil
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return e
}
func runWorkspaceInstall(ctx context.Context, lab string, p *LabProof) error {
	p.Commands = append(p.Commands, "npm ci --ignore-scripts --no-audit --no-fund")
	c := exec.CommandContext(ctx, "npm", "ci", "--registry=https://registry.npmjs.org", "--ignore-scripts", "--no-audit", "--no-fund")
	c.Dir = lab
	c.Env = safeLabEnv()
	o, e := c.CombinedOutput()
	p.InstallPassed = e == nil
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e != nil {
		return errors.New("isolated install failed: " + trimOutput(o))
	}
	return nil
}
func runWorkspaceTests(ctx context.Context, lab string, p *LabProof) {
	p.TestsRun = true
	p.Commands = append(p.Commands, "npm test")
	c := exec.CommandContext(ctx, "npm", "test")
	c.Dir = lab
	c.Env = safeLabEnv()
	o, e := c.CombinedOutput()
	p.TestOutput = trimOutput(o)
	p.TestsPassed = e == nil
}
func finishProof(id, current string, plan Plan, p LabProof, ret error) (LabProof, error) {
	after, e := fileSHA256(current)
	p.WorkingTreeClean = e == nil && after == plan.BaseSHA256
	unsigned := p
	unsigned.ProofSHA256 = ""
	unsigned.Signature = ""
	unsigned.PublicKey = ""
	unsigned.SignatureAlgorithm = ""
	b, _ := json.Marshal(unsigned)
	sum := sha256.Sum256(b)
	p.ProofSHA256 = hex.EncodeToString(sum[:])
	pub, priv, keyErr := proofSigningKey()
	if keyErr == nil {
		p.SignatureAlgorithm = "Ed25519"
		p.PublicKey = base64.StdEncoding.EncodeToString(pub)
		p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(p.ProofSHA256)))
	} else if ret == nil {
		ret = keyErr
	}
	if e = writeProof(id, p); e != nil && ret == nil {
		ret = e
	}
	return p, ret
}
func writeProof(id string, p LabProof) error {
	d := filepath.Join(stateDir(), "proofs")
	if e := os.MkdirAll(d, 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(d, id+".json"), b, 0600)
}
func Proof(id string) (LabProof, error) {
	if strings.ContainsAny(id, `/\\.`) {
		return LabProof{}, errors.New("invalid plan id")
	}
	b, e := os.ReadFile(filepath.Join(stateDir(), "proofs", id+".json"))
	if e != nil {
		return LabProof{}, e
	}
	var p LabProof
	e = json.Unmarshal(b, &p)
	return p, e
}
func copyProjectForLab(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		if rel == "." {
			return nil
		}
		base := d.Name()
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		lower := strings.ToLower(base)
		if !d.IsDir() && (lower == ".npmrc" || lower == ".env" || strings.HasPrefix(lower, ".env.") ||
			lower == ".pypirc" || lower == ".netrc" || lower == "credentials" || strings.HasSuffix(lower, ".pem") ||
			strings.HasSuffix(lower, ".key")) {
			return nil
		}
		if d.IsDir() && (base == ".git" || base == "node_modules" || base == ".secdoctor" || base == "dist" || base == "build") {
			return filepath.SkipDir
		}
		if !d.IsDir() && (base == "Vuln.txt" || strings.HasPrefix(base, "secdoctor-proof.")) {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if info.Size() > 10<<20 {
			return nil
		}
		return copyFile(path, target)
	})
}
func safeLabEnv() []string {
	keep := map[string]bool{"PATH": true, "Path": true, "SystemRoot": true, "SYSTEMROOT": true, "COMSPEC": true, "PATHEXT": true, "TEMP": true, "TMP": true, "LANG": true}
	var out []string
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if keep[k] {
			out = append(out, v)
		}
	}
	return append(out, "CI=true", "NPM_CONFIG_IGNORE_SCRIPTS=true", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org")
}

func proofSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	d := filepath.Join(stateDir(), "keys")
	if e := os.MkdirAll(d, 0700); e != nil {
		return nil, nil, e
	}
	path := filepath.Join(d, "proof-ed25519.key")
	if b, e := os.ReadFile(path); e == nil {
		raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if e == nil && len(raw) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(raw)
			return priv.Public().(ed25519.PublicKey), priv, nil
		}
		return nil, nil, errors.New("invalid SecDoctor proof signing key")
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	if e = os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)), 0600); e != nil {
		return nil, nil, e
	}
	return pub, priv, nil
}

func VerifyProofSignature(p LabProof) error {
	if p.SignatureAlgorithm != "Ed25519" {
		return errors.New("unsupported proof signature algorithm")
	}
	pub, e := base64.StdEncoding.DecodeString(p.PublicKey)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid proof public key")
	}
	trusted, _, keyErr := proofSigningKey()
	if keyErr != nil {
		return errors.New("local proof trust key unavailable")
	}
	if !ed25519.PublicKey(pub).Equal(trusted) {
		return errors.New("proof signer is not trusted by this SecDoctor installation")
	}
	sig, e := base64.StdEncoding.DecodeString(p.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid proof signature")
	}
	unsigned := p
	unsigned.ProofSHA256 = ""
	unsigned.Signature = ""
	unsigned.PublicKey = ""
	unsigned.SignatureAlgorithm = ""
	b, _ := json.Marshal(unsigned)
	sum := sha256.Sum256(b)
	expected := hex.EncodeToString(sum[:])
	if expected != p.ProofSHA256 {
		return errors.New("proof content hash mismatch")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(p.ProofSHA256), sig) {
		return errors.New("proof signature verification failed")
	}
	return nil
}

func validateNPMResolvedSources(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		Packages map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"packages"`
	}
	if err = json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("invalid package-lock.json: %w", err)
	}
	for name, pkg := range doc.Packages {
		raw := strings.TrimSpace(pkg.Resolved)
		if raw == "" {
			continue
		}
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "registry.npmjs.org") {
			return fmt.Errorf("dependency %q resolves outside the allowed npm registry: %q", name, raw)
		}
	}
	return nil
}
