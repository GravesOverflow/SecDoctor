package pkgmodel

import "testing"

func TestPURL(t *testing.T) {
	if got := PURL("npm", "lodash", "4.17.21"); got != "pkg:npm/lodash@4.17.21" {
		t.Fatal(got)
	}
}
func TestScopedNPM(t *testing.T) {
	if got := PURL("npm", "@scope/pkg", "1.0.0"); got != "pkg:npm/%40scope/pkg@1.0.0" {
		t.Fatal(got)
	}
}
