package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"secdoctor/internal/cache"
	"secdoctor/internal/intel"
	"time"
)

type Client struct {
	HTTP  *http.Client
	Cache *cache.FileCache
	URL   string
}

func New(c *cache.FileCache) *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, Cache: c, URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}
}
func (c *Client) Name() string { return "CISA KEV" }
func (c *Client) Enrich(ctx context.Context, v []intel.Vulnerability, offline bool) ([]intel.Vulnerability, error) {
	var rec map[string]intel.KEV
	if ok, e := c.Cache.Get("kev:v3", &rec, offline); e != nil {
		return v, e
	} else if !ok {
		if offline {
			return v, nil
		}
		req, e := http.NewRequestWithContext(ctx, "GET", c.URL, nil)
		if e != nil {
			return v, e
		}
		resp, e := c.HTTP.Do(req)
		if e != nil {
			return v, e
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return v, fmt.Errorf("KEV HTTP %d", resp.StatusCode)
		}
		var d struct {
			Vulnerabilities []struct{ CVEID, DateAdded, DueDate, KnownRansomwareCampaignUse string } `json:"vulnerabilities"`
		}
		if e = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&d); e != nil {
			return v, e
		}
		rec = map[string]intel.KEV{}
		for _, x := range d.Vulnerabilities {
			a, _ := time.Parse("2006-01-02", x.DateAdded)
			b, _ := time.Parse("2006-01-02", x.DueDate)
			rec[x.CVEID] = intel.KEV{KnownExploited: true, DateAdded: a, DueDate: b, RansomwareUse: x.KnownRansomwareCampaignUse}
		}
		if e = c.Cache.Put("kev:v3", rec, 6*time.Hour); e != nil {
			return v, e
		}
	}
	for i := range v {
		if v[i].KEV == nil {
			v[i].KEV = map[string]intel.KEV{}
		}
		for _, id := range v[i].CVEs {
			if x, ok := rec[id]; ok {
				v[i].KEV[id] = x
			}
		}
	}
	return v, nil
}
