package intel

import (
	"context"
	"sort"
	"strings"
	"time"

	"secdoctor/internal/pkgmodel"
)

type CVSS struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
	Rating  string  `json:"rating"`
}
type EPSS struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	Date       time.Time `json:"date,omitempty"`
}
type KEV struct {
	KnownExploited bool      `json:"known_exploited"`
	DateAdded      time.Time `json:"date_added,omitempty"`
	DueDate        time.Time `json:"due_date,omitempty"`
	RansomwareUse  string    `json:"ransomware_use,omitempty"`
}
type Vulnerability struct {
	PrimaryID     string           `json:"primary_id"`
	CVEs          []string         `json:"cves,omitempty"`
	Aliases       []string         `json:"aliases,omitempty"`
	Summary       string           `json:"summary"`
	Package       pkgmodel.Package `json:"package"`
	CVSS          []CVSS           `json:"cvss,omitempty"`
	EPSS          map[string]EPSS  `json:"epss,omitempty"`
	KEV           map[string]KEV   `json:"kev,omitempty"`
	FixedVersions []string         `json:"fixed_versions,omitempty"`
	Sources       []string         `json:"sources,omitempty"`
}
type PackageProvider interface {
	Name() string
	QueryPackages(context.Context, []pkgmodel.Package, bool) ([]Vulnerability, error)
}
type Enricher interface {
	Name() string
	Enrich(context.Context, []Vulnerability, bool) ([]Vulnerability, error)
}

func (v Vulnerability) DisplayID() string {
	if v.PrimaryID != "" {
		return v.PrimaryID
	}
	if len(v.CVEs) > 0 {
		return v.CVEs[0]
	}
	return "UNKNOWN"
}
func (v Vulnerability) PreferredCVE() string {
	if len(v.CVEs) > 0 {
		return v.CVEs[0]
	}
	return ""
}
func (v Vulnerability) HasID(id string) bool {
	id = strings.ToUpper(id)
	if strings.ToUpper(v.PrimaryID) == id {
		return true
	}
	for _, x := range append(append([]string{}, v.CVEs...), v.Aliases...) {
		if strings.ToUpper(x) == id {
			return true
		}
	}
	return false
}
func (v Vulnerability) StableKey() string {
	return strings.ToLower(v.Package.PURL) + "|" + strings.ToUpper(v.PrimaryID)
}
func (v Vulnerability) BestCVSS() *CVSS {
	if len(v.CVSS) == 0 {
		return nil
	}
	b := v.CVSS[0]
	for _, x := range v.CVSS[1:] {
		if x.Score > b.Score {
			b = x
		}
	}
	return &b
}
func (v Vulnerability) MaxEPSS() float64 {
	m := 0.0
	for _, x := range v.EPSS {
		if x.Score > m {
			m = x.Score
		}
	}
	return m
}
func (v Vulnerability) KnownExploited() bool {
	for _, x := range v.KEV {
		if x.KnownExploited {
			return true
		}
	}
	return false
}
func Dedupe(v []Vulnerability) []Vulnerability {
	seen := map[string]int{}
	out := make([]Vulnerability, 0, len(v))
	for _, x := range v {
		k := x.StableKey()
		if n, ok := seen[k]; ok {
			out[n] = merge(out[n], x)
			continue
		}
		seen[k] = len(out)
		out = append(out, x)
	}
	return out
}
func merge(a, b Vulnerability) Vulnerability {
	a.CVEs = uniqueStrings(append(a.CVEs, b.CVEs...))
	a.Aliases = uniqueStrings(append(a.Aliases, b.Aliases...))
	a.FixedVersions = uniqueStrings(append(a.FixedVersions, b.FixedVersions...))
	a.Sources = uniqueStrings(append(a.Sources, b.Sources...))
	a.CVSS = append(a.CVSS, b.CVSS...)
	if a.EPSS == nil {
		a.EPSS = map[string]EPSS{}
	}
	for k, v := range b.EPSS {
		a.EPSS[k] = v
	}
	if a.KEV == nil {
		a.KEV = map[string]KEV{}
	}
	for k, v := range b.KEV {
		a.KEV[k] = v
	}
	if a.Summary == "" {
		a.Summary = b.Summary
	}
	return a
}
func uniqueStrings(xs []string) []string {
	m := map[string]bool{}
	o := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != "" && !m[x] {
			m[x] = true
			o = append(o, x)
		}
	}
	sort.Strings(o)
	return o
}
func Sort(v []Vulnerability) {
	sort.SliceStable(v, func(i, j int) bool {
		if v[i].KnownExploited() != v[j].KnownExploited() {
			return v[i].KnownExploited()
		}
		if v[i].MaxEPSS() != v[j].MaxEPSS() {
			return v[i].MaxEPSS() > v[j].MaxEPSS()
		}
		a, b := 0.0, 0.0
		if x := v[i].BestCVSS(); x != nil {
			a = x.Score
		}
		if x := v[j].BestCVSS(); x != nil {
			b = x.Score
		}
		if a != b {
			return a > b
		}
		return v[i].StableKey() < v[j].StableKey()
	})
}
