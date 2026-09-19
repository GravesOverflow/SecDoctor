package pkgmodel

import (
	"fmt"
	"net/url"
	"strings"
)

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl"`
	Direct    bool   `json:"direct,omitempty"`
	Source    string `json:"source,omitempty"`
}

func New(ecosystem, name, version, source string) Package {
	p := Package{Ecosystem: ecosystem, Name: name, Version: version, Source: source}
	p.PURL = PURL(ecosystem, name, version)
	return p
}

func PURL(ecosystem, name, version string) string {
	t := purlType(ecosystem)
	escaped := escapeName(t, name)
	if version == "" {
		return fmt.Sprintf("pkg:%s/%s", t, escaped)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", t, escaped, url.PathEscape(version))
}

func purlType(e string) string {
	switch strings.ToLower(e) {
	case "pypi":
		return "pypi"
	case "npm":
		return "npm"
	case "go":
		return "golang"
	case "crates.io", "cargo":
		return "cargo"
	case "packagist", "composer":
		return "composer"
	case "nuget":
		return "nuget"
	case "rubygems", "gem":
		return "gem"
	default:
		return strings.ToLower(e)
	}
}

func escapeName(t, name string) string {
	if t == "npm" && strings.HasPrefix(name, "@") {
		parts := strings.SplitN(strings.TrimPrefix(name, "@"), "/", 2)
		if len(parts) == 2 {
			return "%40" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
		}
	}
	if t == "golang" || t == "composer" {
		parts := strings.Split(name, "/")
		for i := range parts {
			parts[i] = url.PathEscape(parts[i])
		}
		return strings.Join(parts, "/")
	}
	return url.PathEscape(name)
}
