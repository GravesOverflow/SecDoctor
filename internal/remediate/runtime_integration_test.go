package remediate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestApplySynchronizesExistingRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake npm helper is POSIX-only; Windows behavior is covered by cross-build and desktop API tests")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("new-lock"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	planDir := filepath.Join(stateDir(), "plans", id)
	if err = os.MkdirAll(planDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(planDir, "package-lock.json"), []byte("candidate-lock"), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := fileSHA256(filepath.Join(root, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{ID: id, Root: root, BaseSHA256: h}
	b, _ := json.Marshal(plan)
	if err = os.WriteFile(filepath.Join(planDir, "plan.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	npm := filepath.Join(bin, "npm")
	if err = os.WriteFile(npm, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	got, err := Apply(context.Background(), id, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RuntimeSynced || got.RuntimeStatus != "verified" {
		t.Fatalf("runtime not verified: %+v", got)
	}
}
