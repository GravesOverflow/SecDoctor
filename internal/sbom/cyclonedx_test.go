package sbom

import (
	"secdoctor/internal/pkgmodel"
	"strings"
	"testing"
)

func TestGenerate17(t *testing.T) {
	b := Generate([]pkgmodel.Package{pkgmodel.New("npm", "lodash", "4.17.21", "package-lock.json")})
	if b.SpecVersion != "1.7" || !strings.HasPrefix(b.SerialNumber, "urn:uuid:") || len(b.Components) != 1 {
		t.Fatalf("%#v", b)
	}
	if b.Components[0].BOMRef == "" || b.Components[0].Properties[0].Value != "npm" {
		t.Fatalf("%#v", b.Components[0])
	}
}
