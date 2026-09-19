package intel

import "testing"

func TestCVSS31(t *testing.T) {
	x, e := ParseCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if e != nil || x.Score != 9.8 || x.Rating != "CRITICAL" {
		t.Fatalf("%#v %v", x, e)
	}
}
func TestIdentity(t *testing.T) {
	v := Vulnerability{PrimaryID: "GHSA-X", CVEs: []string{"CVE-2025-1234"}}
	if !v.HasID("cve-2025-1234") {
		t.Fatal("identity")
	}
}
