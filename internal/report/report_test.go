package report

import (
	"strings"
	"testing"

	"secdoctor/internal/audit"
	"secdoctor/internal/remediate"
)

func TestBuildRedactsProjectPathAndSummarizes(t *testing.T) {
	a := audit.Result{
		Root: `C:\Users\alice\secret-project`, SecurityStatus: "VULNERABILITIES_FOUND",
		ProviderComplete: true, Files: 12, Dependencies: 3, Fingerprint: "abc123",
		Vulnerabilities: []audit.Vulnerability{
			{ID: "GHSA-test", Package: "lodash", Version: "4.17.20", Severity: "HIGH"},
			{ID: "CVE-test", Package: "x", Version: "1.0.0", Severity: "MEDIUM"},
		},
	}
	r := Build(a, "1.0.0-rc3", nil, false)
	if r.Project != "secret-project" {
		t.Fatalf("project=%q", r.Project)
	}
	if r.Severity.High != 1 || r.Severity.Medium != 1 {
		t.Fatalf("severity=%+v", r.Severity)
	}
	b, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `C:\Users\alice`) {
		t.Fatal("absolute path leaked")
	}
}

func TestMarkdownIncludesVerifiedProofWithoutSignatureMaterial(t *testing.T) {
	a := audit.Result{Root: "/tmp/demo", SecurityStatus: "VERIFIED_CLEAN", ProviderComplete: true}
	p := &remediate.LabProof{
		Schema: "secdoctor.proof/v3", Backend: "docker", Assurance: "hardened-container",
		InstallPassed: true, WorkingTreeClean: true, ProofSHA256: "deadbeef",
		SignatureAlgorithm: "Ed25519", Signature: "SECRET_SIGNATURE", PublicKey: "PUBLIC_KEY",
		Changes: []remediate.Change{{Package: "lodash", From: "4.17.20", To: "4.18.0", Direct: true}},
	}
	r := Build(a, "1.0.0-rc3", p, true)
	md := string(Markdown(r))
	if !strings.Contains(md, "Signature verified by this installation: **true**") {
		t.Fatal("verification missing")
	}
	if !strings.Contains(md, "`lodash`: `4.17.20` → `4.18.0`") {
		t.Fatal("change missing")
	}
	if strings.Contains(md, "SECRET_SIGNATURE") || strings.Contains(md, "PUBLIC_KEY") {
		t.Fatal("signature material leaked")
	}
}

func TestFilenameIsSafe(t *testing.T) {
	got := Filename("../../My Project!", "json")
	if got != "secdoctor-report-my-project.json" {
		t.Fatalf("filename=%q", got)
	}
}
