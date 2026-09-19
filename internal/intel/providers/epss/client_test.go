package epss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"secdoctor/internal/cache"
	"secdoctor/internal/intel"
	"testing"
)

func TestEnrichUsesCVEAliases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2025-1234","epss":"0.42","percentile":"0.91","date":"2026-01-01"}]}`))
	}))
	defer srv.Close()
	c := New(&cache.FileCache{Dir: t.TempDir()})
	c.Base = srv.URL
	v := []intel.Vulnerability{{PrimaryID: "GHSA-demo", CVEs: []string{"CVE-2025-1234"}}}
	out, err := c.Enrich(context.Background(), v, false)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].EPSS["CVE-2025-1234"].Score != .42 {
		t.Fatalf("%#v", out[0].EPSS)
	}
}
