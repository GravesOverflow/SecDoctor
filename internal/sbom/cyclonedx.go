package sbom

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"secdoctor/internal/pkgmodel"
)

type BOM struct {
	Schema       string      `json:"$schema,omitempty"`
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components,omitempty"`
}
type Metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     Tools  `json:"tools"`
}
type Tools struct {
	Components []Component `json:"components,omitempty"`
}
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

func Generate(pkgs []pkgmodel.Package) BOM {
	b := BOM{
		Schema:       "https://cyclonedx.org/schema/bom-1.7.schema.json",
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:" + uuidV4(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: Tools{Components: []Component{{
				Type: "application", BOMRef: "secdoctor-tool", Name: "SecDoctor", Version: "0.4.3",
			}}},
		},
	}
	for _, p := range pkgs {
		ref := p.PURL
		if ref == "" {
			ref = fmt.Sprintf("secdoctor:%s:%s:%s", p.Ecosystem, p.Name, p.Version)
		}
		b.Components = append(b.Components, Component{
			Type: "library", BOMRef: ref, Name: p.Name, Version: p.Version, PURL: p.PURL,
			Properties: []Property{{Name: "secdoctor:ecosystem", Value: p.Ecosystem}},
		})
	}
	return b
}
func Write(path string, b BOM) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
func Read(path string) ([]pkgmodel.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}
	var out []pkgmodel.Package
	for _, c := range bom.Components {
		eco := ""
		for _, prop := range c.Properties {
			if prop.Name == "secdoctor:ecosystem" {
				eco = prop.Value
			}
		}
		out = append(out, pkgmodel.Package{Ecosystem: eco, Name: c.Name, Version: c.Version, PURL: c.PURL, Source: path})
	}
	return out, nil
}
func uuidV4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	x := hex.EncodeToString(b)
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}
