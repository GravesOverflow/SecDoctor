package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"secdoctor/internal/cache"
	"secdoctor/internal/intel"
	"secdoctor/internal/pkgmodel"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	HTTP  *http.Client
	Cache *cache.FileCache
	Base  string
}

func New(c *cache.FileCache) *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, Cache: c, Base: "https://api.osv.dev/v1"}
}
func (c *Client) Name() string { return "OSV" }

type query struct {
	Version string `json:"version"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}
type batchReq struct {
	Queries []query `json:"queries"`
}
type batchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		Next string `json:"next_page_token"`
	} `json:"results"`
}
type record struct {
	ID, Summary string
	Aliases     []string
	Severity    []struct{ Type, Score string }
	Affected    []struct {
		Package struct {
			Name, Ecosystem string
			PURL            string `json:"purl"`
		}
		Ranges []struct {
			Events []struct{ Fixed string } `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (c *Client) QueryPackages(ctx context.Context, pkgs []pkgmodel.Package, offline bool) ([]intel.Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PURL < pkgs[j].PURL })
	key := "osv:v4:"
	for _, p := range pkgs {
		key += p.PURL + ";"
	}
	var cached []intel.Vulnerability
	if ok, e := c.Cache.Get(key, &cached, offline); e == nil && ok {
		return cached, nil
	}
	if offline {
		return nil, fmt.Errorf("OSV query not cached")
	}
	brq := batchReq{}
	for _, p := range pkgs {
		q := query{Version: p.Version}
		q.Package.Name = p.Name
		q.Package.Ecosystem = p.Ecosystem
		brq.Queries = append(brq.Queries, q)
	}
	b, e := json.Marshal(brq)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.Base+"/querybatch", bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.doWithRetry(ctx, req, 4)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV HTTP %d", resp.StatusCode)
	}
	var br batchResp
	if e = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&br); e != nil {
		return nil, e
	}
	var out []intel.Vulnerability
	for i, r := range br.Results {
		if i >= len(pkgs) {
			break
		}
		if r.Next != "" {
			return nil, fmt.Errorf("OSV pagination detected; refusing incomplete report")
		}
		for _, h := range r.Vulns {
			rec, e := c.fetch(ctx, h.ID)
			if e != nil {
				return nil, e
			}
			v := normalize(rec, pkgs[i])
			out = append(out, v)
		}
	}
	out = intel.Dedupe(out)
	if e := c.Cache.Put(key, out, 12*time.Hour); e != nil {
		return out, e
	}
	return out, nil
}
func (c *Client) fetch(ctx context.Context, id string) (record, error) {
	key := "osv:record:v4:" + id
	var r record
	if ok, e := c.Cache.Get(key, &r, false); e == nil && ok {
		return r, nil
	}
	req, e := http.NewRequestWithContext(ctx, "GET", c.Base+"/vulns/"+id, nil)
	if e != nil {
		return r, e
	}
	resp, e := c.doWithRetry(ctx, req, 4)
	if e != nil {
		return r, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return r, fmt.Errorf("OSV advisory %s HTTP %d", id, resp.StatusCode)
	}
	e = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r)
	if e != nil {
		return r, e
	}
	if e = c.Cache.Put(key, r, 24*time.Hour); e != nil {
		return r, e
	}
	return r, nil
}
func normalize(r record, p pkgmodel.Package) intel.Vulnerability {
	v := intel.Vulnerability{PrimaryID: r.ID, Aliases: r.Aliases, Summary: r.Summary, Package: p, EPSS: map[string]intel.EPSS{}, KEV: map[string]intel.KEV{}, Sources: []string{"OSV"}}
	for _, a := range append([]string{r.ID}, r.Aliases...) {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			v.CVEs = unique(v.CVEs, strings.ToUpper(a))
		}
	}
	for _, s := range r.Severity {
		if cv, e := intel.ParseCVSS31(s.Score); e == nil {
			v.CVSS = append(v.CVSS, cv)
		}
	}
	for _, a := range r.Affected {
		if a.Package.Name != p.Name || !strings.EqualFold(a.Package.Ecosystem, p.Ecosystem) {
			continue
		}
		for _, rg := range a.Ranges {
			for _, ev := range rg.Events {
				if ev.Fixed != "" {
					v.FixedVersions = unique(v.FixedVersions, ev.Fixed)
				}
			}
		}
	}
	sort.Strings(v.FixedVersions)
	return v
}
func unique(a []string, x string) []string {
	for _, v := range a {
		if v == x {
			return a
		}
	}
	return append(a, x)
}

func (c *Client) doWithRetry(ctx context.Context, req *http.Request, attempts int) (*http.Response, error) {
	if attempts < 1 {
		attempts = 1
	}
	var last string
	for i := 0; i < attempts; i++ {
		clone := req.Clone(ctx)
		if req.GetBody != nil {
			body, e := req.GetBody()
			if e != nil {
				return nil, e
			}
			clone.Body = body
		}
		resp, e := c.HTTP.Do(clone)
		if e == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil
		}
		if e == nil {
			last = fmt.Sprintf("HTTP %d", resp.StatusCode)
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		} else {
			last = e.Error()
		}
		if i == attempts-1 {
			break
		}
		wait := time.Duration(1<<i) * 250 * time.Millisecond
		if e == nil {
			if raw := resp.Header.Get("Retry-After"); raw != "" {
				if sec, parseErr := strconv.Atoi(raw); parseErr == nil && sec >= 0 && sec <= 30 {
					wait = time.Duration(sec) * time.Second
				}
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("provider unavailable after %d attempts: %s", attempts, last)
}
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusRequestTimeout || code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout || code >= 500
}
