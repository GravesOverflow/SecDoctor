package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectsEnvNotIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_MODE=test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("dist/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Project(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(result.Findings, "ENV_NOT_IGNORED") {
		t.Fatalf("expected ENV_NOT_IGNORED, got %#v", result.Findings)
	}
}

func TestIgnoredEnvIsFine(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_MODE=test\n"), 0600)
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env\n"), 0600)
	result, err := Project(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hasID(result.Findings, "ENV_NOT_IGNORED") {
		t.Fatal("did not expect ENV_NOT_IGNORED")
	}
}

func TestSecretRedaction(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.js"), []byte(`const api_key = "abcdefghijklmnop123456789";`), 0600)
	result, err := Project(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !hasID(result.Findings, "SECRET_GENERIC") {
		t.Fatal("expected SECRET_GENERIC")
	}
	for _, f := range result.Findings {
		if f.ID == "SECRET_GENERIC" && f.Evidence == `const api_key = "abcdefghijklmnop123456789";` {
			t.Fatal("secret evidence was not redacted")
		}
	}
}

func hasID(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestResultJSONHasArrayAndDurationMS(t *testing.T) {
	d := t.TempDir()
	r, err := Project(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `"findings":[]`) {
		t.Fatalf("%s", text)
	}
	if !strings.Contains(text, `"duration_ms":`) {
		t.Fatalf("%s", text)
	}
}
