package intel

import (
	"secdoctor/internal/pkgmodel"
	"testing"
)

func TestSortKEV(t *testing.T) {
	v := []Vulnerability{{PrimaryID: "A", EPSS: map[string]EPSS{"A": {Score: .9}}}, {PrimaryID: "B", KEV: map[string]KEV{"B": {KnownExploited: true}}}}
	Sort(v)
	if v[0].PrimaryID != "B" {
		t.Fatal("KEV must sort first")
	}
}

func TestDedupeUsesPrimaryAdvisoryIdentity(t *testing.T) {
	v := []Vulnerability{
		{PrimaryID: "GHSA-a", CVEs: []string{"CVE-1"}, Package: pkg("lodash", "4.17.20")},
		{PrimaryID: "GHSA-b", CVEs: []string{"CVE-1"}, Package: pkg("lodash", "4.17.20")},
		{PrimaryID: "GHSA-a", CVEs: []string{"CVE-1"}, Package: pkg("lodash", "4.17.20")},
	}
	got := Dedupe(v)
	if len(got) != 2 {
		t.Fatalf("got %d; separate advisories sharing a CVE must remain separate", len(got))
	}
}
func pkg(n, v string) pkgmodel.Package { return pkgmodel.New("npm", n, v, "package-lock.json") }
