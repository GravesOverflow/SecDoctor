package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"secdoctor/internal/cache"
	"secdoctor/internal/pkgmodel"
	"strings"
	"testing"
	"time"
)

func TestIdentityCVSSAndFix(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-demo"}]}]}`))
	})
	mux.HandleFunc("/vulns/GHSA-demo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"GHSA-demo","summary":"demo","aliases":["CVE-2025-1234"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"name":"demo","ecosystem":"npm"},"ranges":[{"events":[{"fixed":"2.0.0"}]}]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cl := New(&cache.FileCache{Dir: t.TempDir()})
	cl.Base = srv.URL
	v, err := cl.QueryPackages(context.Background(), []pkgmodel.Package{pkgmodel.New("npm", "demo", "1.0.0", "package-lock.json")}, false)
	if err != nil || len(v) != 1 {
		t.Fatalf("%#v %v", v, err)
	}
	if v[0].PrimaryID != "GHSA-demo" || !v[0].HasID("CVE-2025-1234") {
		t.Fatalf("%#v", v[0])
	}
	if cv := v[0].BestCVSS(); cv == nil || cv.Score != 9.8 {
		t.Fatalf("CVSS %#v", cv)
	}
	if len(v[0].FixedVersions) != 1 || v[0].FixedVersions[0] != "2.0.0" {
		t.Fatalf("%#v", v[0].FixedVersions)
	}
}
func TestPaginationFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[],"next_page_token":"more"}]}`))
	}))
	defer srv.Close()
	cl := New(&cache.FileCache{Dir: t.TempDir()})
	cl.Base = srv.URL
	_, err := cl.QueryPackages(context.Background(), []pkgmodel.Package{pkgmodel.New("npm", "demo", "1.0.0", "x")}, false)
	if err == nil {
		t.Fatal("expected fail-closed pagination error")
	}
}

func TestRetryableProviderStatuses(t *testing.T) {
	for _, code := range []int{429, 500, 502, 503, 504} {
		if !retryableStatus(code) {
			t.Fatalf("%d must be retryable", code)
		}
	}
	for _, code := range []int{400, 401, 403, 404} {
		if retryableStatus(code) {
			t.Fatalf("%d must not be retryable", code)
		}
	}
}
func TestOSVRetries503ThenSucceeds(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	defer srv.Close()
	cl := New(&cache.FileCache{Dir: t.TempDir()})
	cl.Base = srv.URL
	_, err := cl.QueryPackages(context.Background(), []pkgmodel.Package{pkgmodel.New("npm", "demo", "1.0.0", "x")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}
func TestOSV503FailsClosedAfterRetries(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusServiceUnavailable) }))
	defer srv.Close()
	cl := New(&cache.FileCache{Dir: t.TempDir()})
	cl.Base = srv.URL
	_, err := cl.QueryPackages(context.Background(), []pkgmodel.Package{pkgmodel.New("npm", "demo", "1.0.0", "x")}, false)
	if err == nil || !strings.Contains(err.Error(), "provider unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 4 {
		t.Fatalf("expected 4 attempts, got %d", calls)
	}
}
func TestOSVTimeoutFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(100 * time.Millisecond) }))
	defer srv.Close()
	cl := New(&cache.FileCache{Dir: t.TempDir()})
	cl.Base = srv.URL
	cl.HTTP.Timeout = 10 * time.Millisecond
	_, err := cl.QueryPackages(context.Background(), []pkgmodel.Package{pkgmodel.New("npm", "demo", "1.0.0", "x")}, false)
	if err == nil {
		t.Fatal("timeout must not become clean result")
	}
}
