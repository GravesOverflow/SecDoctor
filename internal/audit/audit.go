package audit

import (
	"context"
	"sort"
	"strings"
	"time"

	"secdoctor/internal/cache"
	"secdoctor/internal/intel"
	"secdoctor/internal/intel/providers/epss"
	"secdoctor/internal/intel/providers/kev"
	"secdoctor/internal/intel/providers/osv"
	"secdoctor/internal/packages"
	"secdoctor/internal/pkgmodel"
	"secdoctor/internal/scan"
)

type Stage struct {
	Name       string `json:"name"`
	DurationMS int64  `json:"duration_ms"`
	Status     string `json:"status"`
}

type Vulnerability struct {
	ID             string   `json:"id"`
	CVE            string   `json:"cve,omitempty"`
	Package        string   `json:"package"`
	Version        string   `json:"version"`
	Ecosystem      string   `json:"ecosystem"`
	Source         string   `json:"source,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss,omitempty"`
	EPSS           float64  `json:"epss,omitempty"`
	KnownExploited bool     `json:"known_exploited"`
	FixedVersions  []string `json:"fixed_versions"`
}

type Result struct {
	SecurityStatus   string          `json:"security_status"`
	ProviderComplete bool            `json:"provider_complete"`
	Root             string          `json:"root"`
	Files            int             `json:"files"`
	Bytes            int64           `json:"bytes"`
	Dependencies     int             `json:"dependencies"`
	LocalFindings    []scan.Finding  `json:"local_findings"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities"`
	Warnings         []string        `json:"warnings"`
	Fingerprint      string          `json:"fingerprint"`
	Stages           []Stage         `json:"stages"`
	DurationMS       int64           `json:"duration_ms"`
}

func Run(ctx context.Context, root string, offline bool) (Result, error) {
	started := time.Now()
	out := Result{SecurityStatus: "UNKNOWN", ProviderComplete: false, Root: root, LocalFindings: []scan.Finding{}, Vulnerabilities: []Vulnerability{}, Warnings: []string{}, Stages: []Stage{}}
	stage := func(name string, fn func() error) error {
		t := time.Now()
		err := fn()
		status := "ok"
		if err != nil {
			status = "error"
		}
		out.Stages = append(out.Stages, Stage{Name: name, DurationMS: time.Since(t).Milliseconds(), Status: status})
		return err
	}
	var sr scan.Result
	if err := stage("Files", func() error { var e error; sr, e = scan.Project(root); return e }); err != nil {
		return out, err
	}
	out.Files, out.Bytes, out.Fingerprint, out.LocalFindings = sr.Files, sr.Bytes, sr.Fingerprint, sr.Findings
	out.Warnings = append(out.Warnings, sr.Warnings...)
	var pkgs []pkgmodel.Package
	if err := stage("Dependencies", func() error { var e error; pkgs, e = packages.Discover(root); return e }); err != nil {
		out.Warnings = append(out.Warnings, "Dependencies: "+err.Error())
	}
	out.Dependencies = len(pkgs)
	if len(pkgs) == 0 {
		for _, n := range []string{"OSV", "EPSS", "CISA KEV"} {
			out.Stages = append(out.Stages, Stage{Name: n, Status: "skipped"})
		}
		out.ProviderComplete = true
		out.SecurityStatus = "VERIFIED_CLEAN"
		out.DurationMS = time.Since(started).Milliseconds()
		return out, nil
	}
	c, err := cache.Default()
	if err != nil {
		return out, err
	}
	var vulns []intel.Vulnerability
	if err = stage("OSV", func() error { var e error; vulns, e = osv.New(c).QueryPackages(ctx, pkgs, offline); return e }); err != nil {
		out.Warnings = append(out.Warnings, "OSV: "+err.Error())
		out.SecurityStatus = "PROVIDER_UNAVAILABLE"
		out.ProviderComplete = false
		out.DurationMS = time.Since(started).Milliseconds()
		return out, nil
	}
	if err = stage("EPSS", func() error {
		x, e := epss.New(c).Enrich(ctx, vulns, offline)
		if e == nil {
			vulns = x
		}
		return e
	}); err != nil {
		out.Warnings = append(out.Warnings, "EPSS: "+err.Error())
	}
	if err = stage("CISA KEV", func() error {
		x, e := kev.New(c).Enrich(ctx, vulns, offline)
		if e == nil {
			vulns = x
		}
		return e
	}); err != nil {
		out.Warnings = append(out.Warnings, "CISA KEV: "+err.Error())
	}
	vulns = intel.Dedupe(vulns)
	intel.Sort(vulns)
	for _, v := range vulns {
		item := Vulnerability{ID: v.DisplayID(), CVE: v.PreferredCVE(), Package: v.Package.Name, Version: v.Package.Version, Ecosystem: v.Package.Ecosystem, Source: v.Package.Source, Summary: v.Summary, Severity: "MEDIUM", EPSS: v.MaxEPSS(), KnownExploited: v.KnownExploited(), FixedVersions: append([]string{}, v.FixedVersions...)}
		if cv := v.BestCVSS(); cv != nil {
			item.CVSS = cv.Score
			item.Severity = cv.Rating
			if item.Severity == "" {
				item.Severity = severity(cv.Score)
			}
		}
		out.Vulnerabilities = append(out.Vulnerabilities, item)
	}
	sort.SliceStable(out.LocalFindings, func(i, j int) bool {
		return rank(string(out.LocalFindings[i].Severity)) > rank(string(out.LocalFindings[j].Severity))
	})
	out.ProviderComplete = true
	for _, st := range out.Stages {
		if (st.Name == "EPSS" || st.Name == "CISA KEV") && st.Status == "error" {
			out.ProviderComplete = false
		}
	}
	if len(out.Vulnerabilities) > 0 {
		out.SecurityStatus = "VULNERABILITIES_FOUND"
	} else {
		out.SecurityStatus = "VERIFIED_CLEAN"
	}
	if !out.ProviderComplete {
		out.SecurityStatus = "PARTIAL_RESULTS"
	}
	out.DurationMS = time.Since(started).Milliseconds()
	return out, nil
}
func severity(v float64) string {
	if v >= 9 {
		return "CRITICAL"
	}
	if v >= 7 {
		return "HIGH"
	}
	if v >= 4 {
		return "MEDIUM"
	}
	if v > 0 {
		return "LOW"
	}
	return "UNKNOWN"
}
func rank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}
