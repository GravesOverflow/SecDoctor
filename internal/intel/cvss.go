package intel

import (
	"errors"
	"math"
	"strings"
)

func ParseCVSS31(vector string) (CVSS, error) {
	p := strings.Split(vector, "/")
	if len(p) < 2 || p[0] != "CVSS:3.1" {
		return CVSS{}, errors.New("unsupported CVSS vector")
	}
	m := map[string]string{}
	for _, x := range p[1:] {
		kv := strings.SplitN(x, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	get := func(k string, t map[string]float64) (float64, error) {
		v, ok := t[m[k]]
		if !ok {
			return 0, errors.New("invalid " + k)
		}
		return v, nil
	}
	av, e := get("AV", map[string]float64{"N": .85, "A": .62, "L": .55, "P": .2})
	if e != nil {
		return CVSS{}, e
	}
	ac, e := get("AC", map[string]float64{"L": .77, "H": .44})
	if e != nil {
		return CVSS{}, e
	}
	ui, e := get("UI", map[string]float64{"N": .85, "R": .62})
	if e != nil {
		return CVSS{}, e
	}
	c, e := get("C", map[string]float64{"H": .56, "L": .22, "N": 0})
	if e != nil {
		return CVSS{}, e
	}
	i, e := get("I", map[string]float64{"H": .56, "L": .22, "N": 0})
	if e != nil {
		return CVSS{}, e
	}
	a, e := get("A", map[string]float64{"H": .56, "L": .22, "N": 0})
	if e != nil {
		return CVSS{}, e
	}
	scope := m["S"]
	prt := map[string]float64{"N": .85, "L": .62, "H": .27}
	if scope == "C" {
		prt = map[string]float64{"N": .85, "L": .68, "H": .5}
	} else if scope != "U" {
		return CVSS{}, errors.New("invalid S")
	}
	pr, e := get("PR", prt)
	if e != nil {
		return CVSS{}, e
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if scope == "C" {
		impact = 7.52*(iss-.029) - 3.25*math.Pow(iss-.02, 15)
	}
	exploit := 8.22 * av * ac * pr * ui
	score := 0.0
	if impact > 0 {
		if scope == "U" {
			score = roundUp(math.Min(impact+exploit, 10))
		} else {
			score = roundUp(math.Min(1.08*(impact+exploit), 10))
		}
	}
	rating := "NONE"
	if score >= 9 {
		rating = "CRITICAL"
	} else if score >= 7 {
		rating = "HIGH"
	} else if score >= 4 {
		rating = "MEDIUM"
	} else if score > 0 {
		rating = "LOW"
	}
	return CVSS{Version: "CVSS_V3.1", Vector: vector, Score: score, Rating: rating}, nil
}
func roundUp(x float64) float64 { return math.Ceil((x-1e-10)*10) / 10 }
