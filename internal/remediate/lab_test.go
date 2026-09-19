package remediate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyProjectForLabExcludesSensitiveRuntimeState(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	must := func(path, body string) {
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	must(filepath.Join(src, "package.json"), `{"name":"x"}`)
	must(filepath.Join(src, "src", "index.js"), "ok")
	must(filepath.Join(src, "node_modules", "x", "index.js"), "no")
	must(filepath.Join(src, ".git", "config"), "secret")
	must(filepath.Join(src, "Vuln.txt"), "generated")
	if e := copyProjectForLab(src, dst); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dst, "src", "index.js")); e != nil {
		t.Fatal("source not copied")
	}
	for _, x := range []string{"node_modules", ".git", "Vuln.txt"} {
		if _, e := os.Stat(filepath.Join(dst, x)); !os.IsNotExist(e) {
			t.Fatalf("%s should be excluded", x)
		}
	}
}
func TestSafeLabEnvStripsCredentialNames(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "nope")
	t.Setenv("GITHUB_TOKEN", "nope")
	env := strings.Join(safeLabEnv(), "\n")
	if strings.Contains(env, "AWS_SECRET_ACCESS_KEY") || strings.Contains(env, "GITHUB_TOKEN") {
		t.Fatal("credential leaked into lab env")
	}
	if !strings.Contains(env, "NPM_CONFIG_IGNORE_SCRIPTS=true") {
		t.Fatal("ignore scripts missing")
	}
}

func TestSignedProofDetectsTampering(t *testing.T) {
	p := LabProof{Schema: "secdoctor.proof/v3", PlanID: "unit", ProofSHA256: ""}
	unsigned := p
	b, _ := json.Marshal(unsigned)
	sum := sha256.Sum256(b)
	p.ProofSHA256 = hex.EncodeToString(sum[:])
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	pub, priv, e := proofSigningKey()
	if e != nil {
		t.Fatal(e)
	}
	p.SignatureAlgorithm = "Ed25519"
	p.PublicKey = base64.StdEncoding.EncodeToString(pub)
	p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(p.ProofSHA256)))
	if e = VerifyProofSignature(p); e != nil {
		t.Fatalf("valid proof rejected: %v", e)
	}
	p.Project = "tampered"
	if e = VerifyProofSignature(p); e == nil {
		t.Fatal("tampered proof accepted")
	}
}
func TestSafeLabEnvPinsRegistry(t *testing.T) {
	env := strings.Join(safeLabEnv(), "\n")
	if !strings.Contains(env, "NPM_CONFIG_REGISTRY=https://registry.npmjs.org") {
		t.Fatal("registry is not pinned")
	}
}

func TestCopyProjectForLabExcludesCredentialFiles(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for _, name := range []string{".npmrc", ".env", ".env.production", "client.key", "client.pem", ".netrc", ".pypirc"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "package.json"), []byte(`{"name":"safe"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyProjectForLab(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".npmrc", ".env", ".env.production", "client.key", "client.pem", ".netrc", ".pypirc"} {
		if _, err := os.Stat(filepath.Join(dst, name)); !os.IsNotExist(err) {
			t.Fatalf("%s leaked into lab", name)
		}
	}
}
func TestValidateNPMResolvedSources(t *testing.T) {
	ok := filepath.Join(t.TempDir(), "ok.json")
	if err := os.WriteFile(ok, []byte(`{"packages":{"node_modules/a":{"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateNPMResolvedSources(ok); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"packages":{"node_modules/a":{"resolved":"https://evil.example/a.tgz"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateNPMResolvedSources(bad); err == nil {
		t.Fatal("external resolved host accepted")
	}
}

func TestStrictLabPolicyFlag(t *testing.T) {
	t.Setenv("SECDOCTOR_STRICT_LAB", "1")
	if !strictLabRequired() {
		t.Fatal("strict lab policy not enabled")
	}
	t.Setenv("SECDOCTOR_STRICT_LAB", "0")
	if strictLabRequired() {
		t.Fatal("strict lab policy unexpectedly enabled")
	}
}
func TestDockerImageOverride(t *testing.T) {
	t.Setenv("SECDOCTOR_NODE_IMAGE", "node@example.invalid:deadbeef")
	if got := dockerImage(); got != "node@example.invalid:deadbeef" {
		t.Fatalf("override ignored: %s", got)
	}
}
