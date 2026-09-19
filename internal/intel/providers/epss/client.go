package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"secdoctor/internal/cache"
	"secdoctor/internal/intel"
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
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, Cache: c, Base: "https://api.first.org/data/v1/epss"}
}
func (c *Client) Name() string { return "FIRST EPSS" }
func (c *Client) Enrich(ctx context.Context, v []intel.Vulnerability, offline bool) ([]intel.Vulnerability, error) {
	set := map[string]bool{}
	for _, x := range v {
		for _, id := range x.CVEs {
			set[id] = true
		}
	}
	ids := []string{}
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	all := map[string]intel.EPSS{}
	for _, ids := range chunk(ids, 1500) {
		key := "epss:v3:" + strings.Join(ids, ",")
		var got map[string]intel.EPSS
		if ok, e := c.Cache.Get(key, &got, offline); e != nil {
			return v, e
		} else if !ok {
			if offline {
				continue
			}
			req, e := http.NewRequestWithContext(ctx, "GET", c.Base+"?cve="+url.QueryEscape(strings.Join(ids, ",")), nil)
			if e != nil {
				return v, e
			}
			resp, e := c.HTTP.Do(req)
			if e != nil {
				return v, e
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return v, fmt.Errorf("EPSS HTTP %d", resp.StatusCode)
			}
			var r struct {
				Data []struct{ CVE, EPSS, Percentile, Date string } `json:"data"`
			}
			if e = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r); e != nil {
				return v, e
			}
			got = map[string]intel.EPSS{}
			for _, d := range r.Data {
				s, e1 := strconv.ParseFloat(d.EPSS, 64)
				p, e2 := strconv.ParseFloat(d.Percentile, 64)
				if e1 != nil || e2 != nil {
					continue
				}
				dt, _ := time.Parse("2006-01-02", d.Date)
				got[d.CVE] = intel.EPSS{Score: s, Percentile: p, Date: dt}
			}
			if e = c.Cache.Put(key, got, 24*time.Hour); e != nil {
				return v, e
			}
		}
		for k, x := range got {
			all[k] = x
		}
	}
	for i := range v {
		if v[i].EPSS == nil {
			v[i].EPSS = map[string]intel.EPSS{}
		}
		for _, id := range v[i].CVEs {
			if x, ok := all[id]; ok {
				v[i].EPSS[id] = x
			}
		}
	}
	return v, nil
}
func chunk(ids []string, max int) [][]string {
	var o [][]string
	var c []string
	n := 0
	for _, id := range ids {
		z := len(id)
		if len(c) > 0 {
			z++
		}
		if n+z > max {
			o = append(o, c)
			c = nil
			n = 0
		}
		c = append(c, id)
		n += z
	}
	if len(c) > 0 {
		o = append(o, c)
	}
	return o
}
