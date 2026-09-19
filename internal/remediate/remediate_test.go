package remediate

import (
	"os"
	"path/filepath"
	"testing"

	"secdoctor/internal/pkgmodel"
)

func TestComparePrefersChangedPackagesAndDirectFirst(t *testing.T) {
	before := []pkgmodel.Package{
		func() pkgmodel.Package {
			x := pkgmodel.New("npm", "transitive", "1.0.0", "package-lock.json")
			return x
		}(),
		func() pkgmodel.Package {
			x := pkgmodel.New("npm", "lodash", "4.17.20", "package-lock.json")
			x.Direct = true
			return x
		}(),
	}
	after := []pkgmodel.Package{
		pkgmodel.New("npm", "transitive", "1.1.0", "package-lock.json"),
		pkgmodel.New("npm", "lodash", "4.17.21", "package-lock.json"),
	}
	got := compare(before, after)
	if len(got) != 2 {
		t.Fatalf("got %d changes", len(got))
	}
	if got[0].Package != "lodash" || got[0].From != "4.17.20" || got[0].To != "4.17.21" || !got[0].Direct {
		t.Fatalf("unexpected direct change: %+v", got[0])
	}
}

func TestDetectTestCommandRejectsDefaultNPMPlaceholder(t *testing.T) {
	d := t.TempDir()
	body := `{"scripts":{"test":"echo \"Error: no test specified\" && exit 1"}}`
	if err := os.WriteFile(filepath.Join(d, "package.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if got := detectTestCommand(d); got != "" {
		t.Fatalf("expected no test command, got %q", got)
	}
}

func TestFileSHA256Stable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, []byte("secdoctor"), 0600); err != nil {
		t.Fatal(err)
	}
	a, e := fileSHA256(p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := fileSHA256(p)
	if e != nil {
		t.Fatal(e)
	}
	if a == "" || a != b {
		t.Fatalf("unstable hash: %q %q", a, b)
	}
}

func TestRequestedTargetsOnlyDirectPackages(t *testing.T) {
	direct := pkgmodel.New("npm", "lodash", "4.17.20", "package-lock.json")
	direct.Direct = true
	transitive := pkgmodel.New("npm", "other", "1.0.0", "package-lock.json")
	got := requestedTargets([]pkgmodel.Package{direct, transitive}, map[string]string{"lodash": "4.18.0", "other": "2.0.0"})
	if len(got) != 1 || got[0] != "lodash@4.18.0" {
		t.Fatalf("unexpected targets: %#v", got)
	}
}

func TestRuntimeStatusDefaultsAreExplicit(t *testing.T) {
	r := ApplyResult{RuntimeStatus: "not_requested"}
	if r.RuntimeSynced {
		t.Fatal("runtime must not be reported synchronized by default")
	}
	if r.RuntimeStatus != "not_requested" {
		t.Fatal("runtime status must be explicit")
	}
}

func TestRollbackRuntimeVersionVerification(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "lodash")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"version":"4.17.20"}`), 0600); err != nil {
		t.Fatal(err)
	}
	changes := []Change{{Package: "lodash", From: "4.17.20", To: "4.18.0", Direct: true}}
	if err := verifyChangedRuntimeVersionsRollback(root, changes); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"version":"4.18.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyChangedRuntimeVersionsRollback(root, changes); err == nil {
		t.Fatal("wrong rollback runtime version accepted")
	}
}
