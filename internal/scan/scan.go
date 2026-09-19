package scan

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Severity string

const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
	Low    Severity = "LOW"
)

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Explanation string   `json:"explanation"`
	Fix         string   `json:"fix"`
}

type Result struct {
	Root            string    `json:"root"`
	Files           int       `json:"files_scanned"`
	Bytes           int64     `json:"bytes_scanned"`
	DurationMS      int64     `json:"duration_ms"`
	Findings        []Finding `json:"findings"`
	Fingerprint     string    `json:"fingerprint"`
	Packages        int       `json:"packages_checked,omitempty"`
	Vulnerabilities int       `json:"vulnerabilities_found,omitempty"`
	CVESources      []string  `json:"cve_sources,omitempty"`
	Warnings        []string  `json:"warnings,omitempty"`
}

var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"venv": true, "dist": true, "build": true, ".next": true, "target": true,
}

var secretRules = []struct {
	id, title string
	re        *regexp.Regexp
}{
	{"SECRET_PRIVATE_KEY", "Private key material detected", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"SECRET_AWS_KEY", "Possible AWS access key detected", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"SECRET_GITHUB_TOKEN", "Possible GitHub token detected", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,255}\b`)},
	{"SECRET_GENERIC", "Possible hard-coded secret detected", regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"'\s]{12,}["']`)},
}

func Project(root string) (Result, error) {
	started := time.Now()
	res := Result{Root: root, Findings: make([]Finding, 0)}
	h := sha256.New()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			res.Warnings = append(res.Warnings, "walk: "+err.Error())
			return nil
		}
		if d.IsDir() {
			if path != root && skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2*1024*1024 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		res.Files++
		res.Bytes += info.Size()
		io.WriteString(h, rel)
		io.WriteString(h, strconv.FormatInt(info.Size(), 10))

		if isProbablyText(path) {
			scanTextFile(root, path, &res)
		}
		return nil
	})
	if err != nil {
		return res, err
	}

	checkProjectFiles(root, &res)
	scanExtra(root, &res)
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return severityRank(res.Findings[i].Severity) > severityRank(res.Findings[j].Severity)
	})
	res.Fingerprint = hex.EncodeToString(h.Sum(nil))[:16]
	res.DurationMS = time.Since(started).Milliseconds()
	return res, nil
}

func scanTextFile(root, path string, res *Result) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	rel, _ := filepath.Rel(root, path)
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 1024*1024)
	line := 0
	for s.Scan() {
		line++
		text := s.Text()
		for _, rule := range secretRules {
			if rule.re.MatchString(text) {
				res.Findings = append(res.Findings, Finding{
					ID: rule.id, Severity: High, Title: rule.title, File: rel, Line: line,
					Evidence:    redact(text),
					Explanation: "Credentials committed to source code can leak through repositories, logs, archives, or build artifacts.",
					Fix:         "Remove the credential from the file, rotate/revoke it, and load secrets from environment variables or a secret manager.",
				})
			}
		}
	}
	if err := s.Err(); err != nil {
		res.Warnings = append(res.Warnings, "scan "+rel+": "+err.Error())
	}
}

func checkProjectFiles(root string, res *Result) {
	docker := filepath.Join(root, "Dockerfile")
	if b, err := os.ReadFile(docker); err == nil {
		text := string(b)
		if !regexp.MustCompile(`(?mi)^\s*USER\s+\S+`).MatchString(text) {
			res.Findings = append(res.Findings, Finding{
				ID: "DOCKER_ROOT", Severity: Medium, Title: "Docker image may run as root", File: "Dockerfile",
				Explanation: "Containers run as root by default unless a USER directive changes the runtime user.",
				Fix:         "Create a dedicated unprivileged user and add a USER directive before the final CMD or ENTRYPOINT.",
			})
		}
		if strings.Contains(text, "ADD http://") || strings.Contains(text, "ADD https://") {
			res.Findings = append(res.Findings, Finding{
				ID: "DOCKER_REMOTE_ADD", Severity: Low, Title: "Dockerfile downloads remote content with ADD", File: "Dockerfile",
				Explanation: "Remote build inputs make provenance and integrity harder to review.",
				Fix:         "Prefer an explicit download step with HTTPS and verify a pinned checksum.",
			})
		}
	}

	env := filepath.Join(root, ".env")
	if _, err := os.Stat(env); err == nil {
		gitignore, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
		if !containsIgnoreLine(string(gitignore), ".env") {
			res.Findings = append(res.Findings, Finding{
				ID: "ENV_NOT_IGNORED", Severity: High, Title: ".env exists but is not ignored by Git", File: ".gitignore",
				Explanation: ".env files commonly contain credentials and may be committed accidentally.",
				Fix:         "Add .env to .gitignore. If it was already committed, remove it from tracking and rotate exposed credentials.",
			})
		}
	}

	if b, err := os.ReadFile(filepath.Join(root, "package.json")); err == nil {
		if regexp.MustCompile(`"[^"]+"\s*:\s*"\*"`).Match(b) {
			res.Findings = append(res.Findings, Finding{
				ID: "NPM_WILDCARD", Severity: Low, Title: "Review wildcard dependency versions", File: "package.json",
				Explanation: "Unbounded dependency versions reduce reproducibility and can unexpectedly introduce breaking or unsafe releases.",
				Fix:         "Pin an appropriate version range and commit the package lockfile.",
			})
		}
	}
}

func containsIgnoreLine(s, target string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == target || line == target+"/" {
			return true
		}
	}
	return false
}

func redact(s string) string {
	s = strings.TrimSpace(s)
	return "[redacted]"
}

func isProbablyText(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2":
		return false
	default:
		return true
	}
}

func severityRank(s Severity) int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	default:
		return 1
	}
}
