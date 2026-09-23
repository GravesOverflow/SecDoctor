package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"secdoctor/internal/audit"
	"secdoctor/internal/remediate"
	"secdoctor/internal/scan"
)

const Schema = "secdoctor.report/v1"

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type ProofSummary struct {
	Present          bool               `json:"present"`
	Verified         bool               `json:"verified"`
	Schema           string             `json:"schema,omitempty"`
	Backend          string             `json:"backend,omitempty"`
	Assurance        string             `json:"assurance,omitempty"`
	InstallPassed    bool               `json:"install_passed"`
	TestsRun         bool               `json:"tests_run"`
	TestsPassed      bool               `json:"tests_passed"`
	WorkingTreeClean bool               `json:"working_tree_untouched"`
	ProofSHA256      string             `json:"proof_sha256,omitempty"`
	Signature        string             `json:"signature_algorithm,omitempty"`
	Changes          []remediate.Change `json:"changes,omitempty"`
}

type SecurityReport struct {
	Schema           string                `json:"schema"`
	GeneratedAt      string                `json:"generated_at"`
	SecDoctorVersion string                `json:"secdoctor_version"`
	Project          string                `json:"project"`
	SecurityStatus   string                `json:"security_status"`
	ProviderComplete bool                  `json:"provider_complete"`
	Files            int                   `json:"files"`
	Dependencies     int                   `json:"dependencies"`
	Fingerprint      string                `json:"fingerprint"`
	Severity         SeverityCounts        `json:"severity"`
	Vulnerabilities  []audit.Vulnerability `json:"vulnerabilities"`
	LocalFindings    []scan.Finding        `json:"local_findings"`
	Warnings         []string              `json:"warnings,omitempty"`
	Stages           []audit.Stage         `json:"stages"`
	Proof            *ProofSummary         `json:"remediation_proof,omitempty"`
}

func Build(a audit.Result, version string, proof *remediate.LabProof, proofVerified bool) SecurityReport {
	r := SecurityReport{
		Schema: Schema, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SecDoctorVersion: version, Project: projectName(a.Root),
		SecurityStatus: a.SecurityStatus, ProviderComplete: a.ProviderComplete,
		Files: a.Files, Dependencies: a.Dependencies, Fingerprint: a.Fingerprint,
		Vulnerabilities: append([]audit.Vulnerability(nil), a.Vulnerabilities...),
		LocalFindings:   append([]scan.Finding(nil), a.LocalFindings...),
		Warnings:        sanitizeWarnings(a.Warnings), Stages: append([]audit.Stage(nil), a.Stages...),
	}
	for _, v := range r.Vulnerabilities {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			r.Severity.Critical++
		case "HIGH":
			r.Severity.High++
		case "MEDIUM":
			r.Severity.Medium++
		case "LOW":
			r.Severity.Low++
		default:
			r.Severity.Unknown++
		}
	}
	if proof != nil {
		r.Proof = &ProofSummary{
			Present: true, Verified: proofVerified, Schema: proof.Schema, Backend: proof.Backend,
			Assurance: proof.Assurance, InstallPassed: proof.InstallPassed, TestsRun: proof.TestsRun,
			TestsPassed: proof.TestsPassed, WorkingTreeClean: proof.WorkingTreeClean,
			ProofSHA256: proof.ProofSHA256, Signature: proof.SignatureAlgorithm,
			Changes: append([]remediate.Change(nil), proof.Changes...),
		}
	}
	return r
}

func JSON(r SecurityReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func Markdown(r SecurityReport) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# SecDoctor Security Report\n\n")
	fmt.Fprintf(&b, "- **Project:** %s\n- **Generated:** %s\n- **SecDoctor:** %s\n", md(r.Project), r.GeneratedAt, md(r.SecDoctorVersion))
	fmt.Fprintf(&b, "- **Security status:** `%s`\n- **Provider complete:** %t\n- **Fingerprint:** `%s`\n\n", md(r.SecurityStatus), r.ProviderComplete, md(r.Fingerprint))
	fmt.Fprintf(&b, "## Summary\n\n| Critical | High | Medium | Low | Unknown | Dependencies | Files |\n|---:|---:|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d | %d |\n\n", r.Severity.Critical, r.Severity.High, r.Severity.Medium, r.Severity.Low, r.Severity.Unknown, r.Dependencies, r.Files)

	fmt.Fprintf(&b, "## Known dependency vulnerabilities\n\n")
	if len(r.Vulnerabilities) == 0 {
		b.WriteString("No known dependency vulnerabilities were returned by the completed provider set.\n\n")
	} else {
		for _, v := range r.Vulnerabilities {
			fmt.Fprintf(&b, "### %s — %s@%s\n\n", md(v.ID), md(v.Package), md(v.Version))
			fmt.Fprintf(&b, "- Severity: **%s**", md(v.Severity))
			if v.CVSS > 0 {
				fmt.Fprintf(&b, " (CVSS %.1f)", v.CVSS)
			}
			b.WriteString("\n")
			if v.CVE != "" {
				fmt.Fprintf(&b, "- CVE: `%s`\n", md(v.CVE))
			}
			if v.EPSS > 0 {
				fmt.Fprintf(&b, "- EPSS: %.2f%%\n", v.EPSS*100)
			}
			fmt.Fprintf(&b, "- CISA KEV: %t\n", v.KnownExploited)
			if len(v.FixedVersions) > 0 {
				fmt.Fprintf(&b, "- Fixed versions: %s\n", md(strings.Join(v.FixedVersions, ", ")))
			}
			if v.Summary != "" {
				fmt.Fprintf(&b, "\n%s\n", md(v.Summary))
			}
			b.WriteString("\n")
		}
	}

	fmt.Fprintf(&b, "## Local checks\n\n")
	if len(r.LocalFindings) == 0 {
		b.WriteString("No local file or configuration findings.\n\n")
	} else {
		for _, f := range r.LocalFindings {
			fmt.Fprintf(&b, "- **%s — %s**", md(string(f.Severity)), md(f.Title))
			if f.File != "" {
				fmt.Fprintf(&b, " (`%s`)", md(filepath.ToSlash(f.File)))
			}
			fmt.Fprintf(&b, ": %s\n", md(f.Explanation))
		}
		b.WriteString("\n")
	}

	if r.Proof != nil {
		fmt.Fprintf(&b, "## Remediation proof\n\n")
		fmt.Fprintf(&b, "- Signature verified by this installation: **%t**\n", r.Proof.Verified)
		fmt.Fprintf(&b, "- Backend: `%s`\n- Assurance: `%s`\n- Install passed: %t\n", md(r.Proof.Backend), md(r.Proof.Assurance), r.Proof.InstallPassed)
		fmt.Fprintf(&b, "- Original project untouched during Lab: %t\n- Signature: `%s`\n- Proof SHA-256: `%s`\n", r.Proof.WorkingTreeClean, md(r.Proof.Signature), md(r.Proof.ProofSHA256))
		if r.Proof.TestsRun {
			fmt.Fprintf(&b, "- Tests passed: %t\n", r.Proof.TestsPassed)
		}
		if len(r.Proof.Changes) > 0 {
			b.WriteString("\n### Reviewed changes\n\n")
			for _, c := range r.Proof.Changes {
				fmt.Fprintf(&b, "- `%s`: `%s` → `%s`\n", md(c.Package), md(c.From), md(c.To))
			}
		}
		b.WriteString("\n")
	}

	if len(r.Warnings) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "- %s\n", md(w))
		}
		b.WriteString("\n")
	}
	b.WriteString("> This report records SecDoctor's observed scan state. It is not a guarantee that the project is vulnerability-free.\n")
	return []byte(b.String())
}

func Filename(project, ext string) string {
	name := strings.ToLower(projectName(project))
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
	name = strings.Trim(name, "-")
	if name == "" {
		name = "project"
	}
	if ext != "json" {
		ext = "md"
	}
	return "secdoctor-report-" + name + "." + ext
}

func projectName(root string) string {
	clean := strings.TrimSpace(strings.ReplaceAll(root, "\\", "/"))
	clean = strings.TrimRight(clean, "/")
	if clean == "" || clean == "." {
		return "project"
	}
	if i := strings.LastIndex(clean, "/"); i >= 0 {
		clean = clean[i+1:]
	}
	if clean == "" || clean == "." {
		return "project"
	}
	return clean
}

func sanitizeWarnings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, w := range in {
		// Warnings are provider/status evidence. Strip line breaks so an upstream error
		// cannot inject additional Markdown report structure.
		w = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(w, "\r", " "), "\n", " "))
		if w != "" {
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}

func md(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "`", "\\`", "|", "\\|", "\r", " ", "\n", " ")
	return r.Replace(strings.TrimSpace(s))
}

// Print preserves the original terminal report used by older callers.
func Print(r scan.Result) {
	fmt.Println("╭──────────────────────────────────────────────────────────╮")
	fmt.Println("│  🩺 SecDoctor — project security checkup                 │")
	fmt.Println("╰──────────────────────────────────────────────────────────╯")
	fmt.Printf("\nProject: %s\n", r.Root)
	fmt.Printf("Scanned: %d files · %s · fingerprint %s\n", r.Files, humanBytes(r.Bytes), r.Fingerprint)
	if r.Packages > 0 {
		fmt.Printf("Dependencies: %d checked · %d known vulnerabilities found\n", r.Packages, r.Vulnerabilities)
	}
	for _, warning := range r.Warnings {
		fmt.Printf("Warning: %s\n", warning)
	}
	fmt.Println()
	if len(r.Findings) == 0 {
		fmt.Println("✓ No findings from the enabled checks.")
		fmt.Println("\nNote: this is a focused static check, not a guarantee that the project is vulnerability-free.")
		return
	}
	fmt.Printf("Found %d issue(s)\n\n", len(r.Findings))
	for i, f := range r.Findings {
		where := ""
		if f.File != "" {
			where = "  " + f.File
			if f.Line > 0 {
				where += fmt.Sprintf(":%d", f.Line)
			}
		}
		fmt.Printf("%d. [%s] %s%s\n", i+1, f.Severity, f.Title, where)
		fmt.Printf("   Why: %s\n   Fix: %s\n", f.Explanation, f.Fix)
		if f.Evidence != "" {
			fmt.Printf("   Evidence: %s\n", f.Evidence)
		}
		fmt.Println()
	}
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Completed in %dms. Run `secdoctor explain .` for optional AI analysis.\n", r.DurationMS)
}

func humanBytes(n int64) string {
	const kb = 1024
	if n < kb {
		return fmt.Sprintf("%d B", n)
	}
	if n < kb*kb {
		return fmt.Sprintf("%.1f KB", float64(n)/kb)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(kb*kb))
}
