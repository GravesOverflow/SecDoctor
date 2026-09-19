package packages

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"secdoctor/internal/pkgmodel"
)

type Parser interface {
	Name() string
	Detect(string) bool
	Parse(string) ([]pkgmodel.Package, error)
}
type fileParser struct {
	name, file string
	parse      func(string) ([]pkgmodel.Package, error)
}

func (p fileParser) Name() string { return p.name }
func (p fileParser) Detect(root string) bool {
	_, e := os.Stat(filepath.Join(root, p.file))
	return e == nil
}
func (p fileParser) Parse(root string) ([]pkgmodel.Package, error) {
	return p.parse(filepath.Join(root, p.file))
}

func Registry() []Parser {
	return []Parser{
		fileParser{"npm", "package-lock.json", parsePackageLock},
		fileParser{"pnpm", "pnpm-lock.yaml", parsePNPM},
		fileParser{"yarn", "yarn.lock", parseYarn},
		fileParser{"requirements", "requirements.txt", parseRequirements},
		fileParser{"poetry", "poetry.lock", parsePoetry},
		fileParser{"pipenv", "Pipfile.lock", parsePipenv},
		fileParser{"uv", "uv.lock", parseUV},
		fileParser{"go", "go.sum", parseGoSum},
		fileParser{"cargo", "Cargo.lock", parseCargo},
		fileParser{"composer", "composer.lock", parseComposer},
		fileParser{"nuget", "packages.lock.json", parseNuget},
		fileParser{"rubygems", "Gemfile.lock", parseGem},
	}
}

func Discover(root string) ([]pkgmodel.Package, error) {
	var out []pkgmodel.Package
	for _, p := range Registry() {
		if !p.Detect(root) {
			continue
		}
		x, err := p.Parse(root)
		if err != nil {
			return nil, err
		}
		out = append(out, x...)
	}
	seen := map[string]bool{}
	uniq := make([]pkgmodel.Package, 0, len(out))
	for _, p := range out {
		k := p.PURL
		if p.Version != "" && !seen[k] {
			seen[k] = true
			uniq = append(uniq, p)
		}
	}
	return uniq, nil
}

func parsePackageLock(path string) ([]pkgmodel.Package, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var d struct {
		Packages map[string]struct {
			Version         string            `json:"version"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
			Optional        map[string]string `json:"optionalDependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	direct := map[string]bool{}
	if rootPkg, ok := d.Packages[""]; ok {
		for n := range rootPkg.Dependencies {
			direct[n] = true
		}
		for n := range rootPkg.DevDependencies {
			direct[n] = true
		}
		for n := range rootPkg.Optional {
			direct[n] = true
		}
	}
	var out []pkgmodel.Package
	for k, v := range d.Packages {
		if k == "" || v.Version == "" {
			continue
		}
		n := strings.TrimPrefix(k, "node_modules/")
		if i := strings.LastIndex(n, "node_modules/"); i >= 0 {
			n = n[i+13:]
		}
		pkg := pkgmodel.New("npm", n, v.Version, filepath.Base(path))
		pkg.Direct = direct[n]
		out = append(out, pkg)
	}
	return out, nil
}
func parseRequirements(path string) ([]pkgmodel.Package, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	re := regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)==([^\s;]+)`)
	var out []pkgmodel.Package
	s := bufio.NewScanner(f)
	for s.Scan() {
		m := re.FindStringSubmatch(s.Text())
		if len(m) == 3 {
			out = append(out, pkgmodel.New("PyPI", m[1], m[2], filepath.Base(path)))
		}
	}
	return out, s.Err()
}
func parseGoSum(path string) ([]pkgmodel.Package, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []pkgmodel.Package
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Fields(s.Text())
		if len(x) >= 2 {
			v := strings.TrimSuffix(x[1], "/go.mod")
			out = append(out, pkgmodel.New("Go", x[0], v, filepath.Base(path)))
		}
	}
	return out, s.Err()
}
func parseCargo(path string) ([]pkgmodel.Package, error)  { return parseTomlPackages(path, "crates.io") }
func parsePoetry(path string) ([]pkgmodel.Package, error) { return parseTomlPackages(path, "PyPI") }
func parseUV(path string) ([]pkgmodel.Package, error)     { return parseTomlPackages(path, "PyPI") }
func parseTomlPackages(path, eco string) ([]pkgmodel.Package, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []pkgmodel.Package
	name, ver := "", ""
	s := bufio.NewScanner(f)
	flush := func() {
		if name != "" && ver != "" {
			out = append(out, pkgmodel.New(eco, name, ver, filepath.Base(path)))
		}
		name, ver = "", ""
	}
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(l, "name = ") {
			name = strings.Trim(strings.TrimSpace(l[7:]), `"`)
		}
		if strings.HasPrefix(l, "version = ") {
			ver = strings.Trim(strings.TrimSpace(l[10:]), `"`)
		}
	}
	flush()
	return out, s.Err()
}
func parseComposer(path string) ([]pkgmodel.Package, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var d struct {
		Packages []struct{ Name, Version string } `json:"packages"`
		Dev      []struct{ Name, Version string } `json:"packages-dev"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	var out []pkgmodel.Package
	for _, p := range append(d.Packages, d.Dev...) {
		out = append(out, pkgmodel.New("Packagist", p.Name, strings.TrimPrefix(p.Version, "v"), filepath.Base(path)))
	}
	return out, nil
}
func parsePipenv(path string) ([]pkgmodel.Package, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var d map[string]map[string]map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	var out []pkgmodel.Package
	for _, section := range []string{"default", "develop"} {
		for n, m := range d[section] {
			if v, ok := m["version"].(string); ok && strings.HasPrefix(v, "==") {
				out = append(out, pkgmodel.New("PyPI", n, strings.TrimPrefix(v, "=="), filepath.Base(path)))
			}
		}
	}
	return out, nil
}
func parseNuget(path string) ([]pkgmodel.Package, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var d struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	var out []pkgmodel.Package
	for _, fw := range d.Dependencies {
		for n, p := range fw {
			if p.Resolved != "" {
				out = append(out, pkgmodel.New("NuGet", n, p.Resolved, filepath.Base(path)))
			}
		}
	}
	return out, nil
}
func parsePNPM(path string) ([]pkgmodel.Package, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	re := regexp.MustCompile(`^\s{2,}/?(@?[^/:\s]+(?:/[^/:\s]+)?)/([^:\s]+):\s*$`)
	var out []pkgmodel.Package
	s := bufio.NewScanner(f)
	for s.Scan() {
		m := re.FindStringSubmatch(s.Text())
		if len(m) == 3 {
			out = append(out, pkgmodel.New("npm", m[1], m[2], filepath.Base(path)))
		}
	}
	return out, s.Err()
}
func parseYarn(path string) ([]pkgmodel.Package, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []pkgmodel.Package
	s := bufio.NewScanner(f)
	name := ""
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if !strings.HasPrefix(l, "#") && strings.HasSuffix(l, ":") && !strings.HasPrefix(l, "version ") {
			key := strings.TrimSuffix(l, ":")
			key = strings.Trim(key, `"`)
			if i := strings.LastIndex(key, "@"); i > 0 {
				name = key[:i]
			}
		} else if name != "" && strings.HasPrefix(l, "version ") {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "version ")), `"`)
			out = append(out, pkgmodel.New("npm", name, v, filepath.Base(path)))
			name = ""
		}
	}
	return out, s.Err()
}
func parseGem(path string) ([]pkgmodel.Package, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	re := regexp.MustCompile(`^\s{4}([A-Za-z0-9_.-]+) \(([^),]+)`)
	var out []pkgmodel.Package
	s := bufio.NewScanner(f)
	for s.Scan() {
		m := re.FindStringSubmatch(s.Text())
		if len(m) == 3 {
			out = append(out, pkgmodel.New("RubyGems", m[1], m[2], filepath.Base(path)))
		}
	}
	return out, s.Err()
}
