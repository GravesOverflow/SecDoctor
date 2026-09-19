package packages

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequirementsExactOnly(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "requirements.txt"), []byte("requests==2.31.0\nflask>=2\n"), 0600)
	p, e := Discover(d)
	if e != nil || len(p) != 1 || p[0].Name != "requests" {
		t.Fatalf("%#v %v", p, e)
	}
}
func TestNuget(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "packages.lock.json"), []byte(`{"dependencies":{"net8.0":{"Newtonsoft.Json":{"resolved":"13.0.3"}}}}`), 0600)
	p, e := Discover(d)
	if e != nil || len(p) != 1 || p[0].Ecosystem != "NuGet" {
		t.Fatalf("%#v %v", p, e)
	}
}

func TestPackageLockDirectness(t *testing.T) {
	d := t.TempDir()
	data := `{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0"},"node_modules/b":{"version":"2.0.0"}}}`
	if err := os.WriteFile(filepath.Join(d, "package-lock.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := parsePackageLock(filepath.Join(d, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, x := range p {
		m[x.Name] = x.Direct
	}
	if !m["a"] || m["b"] {
		t.Fatalf("directness %#v", m)
	}
}
