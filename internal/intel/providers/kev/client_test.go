package kev

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
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2025-1234","dateAdded":"2026-01-01","dueDate":"2026-01-20","knownRansomwareCampaignUse":"Unknown"}]}`))
	}))
	defer srv.Close()
	c := New(&cache.FileCache{Dir: t.TempDir()})
	c.URL = srv.URL
	v := []intel.Vulnerability{{PrimaryID: "GHSA-demo", CVEs: []string{"CVE-2025-1234"}}}
	out, err := c.Enrich(context.Background(), v, false)
	if err != nil {
		t.Fatal(err)
	}
	if !out[0].KnownExploited() {
		t.Fatalf("%#v", out[0].KEV)
	}
}
