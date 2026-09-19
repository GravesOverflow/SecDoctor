package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func scanExtra(root string, res *Result) {
	checkGitHubActions(root, res)
	checkCompose(root, res)
	checkSensitiveFiles(root, res)
}

func checkGitHubActions(root string, res *Result) {
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	sha := regexp.MustCompile(`(?i)uses:\s*[^@\s]+@([0-9a-f]{40})\b`)
	uses := regexp.MustCompile(`(?i)^\s*uses:\s*[^@\s]+@([^\s#]+)`)
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		line := 0
		for s.Scan() {
			line++
			text := s.Text()
			if m := uses.FindStringSubmatch(text); len(m) == 2 && !strings.Contains(text, "uses: ./") && !sha.MatchString(text) {
				res.Findings = append(res.Findings, Finding{
					ID: "GHA_UNPINNED_ACTION", Severity: Medium, Title: "GitHub Action is not pinned to a full commit SHA",
					File: filepath.ToSlash(filepath.Join(".github", "workflows", e.Name())), Line: line,
					Explanation: "Tag and branch references can move. Pinning third-party actions to a reviewed commit reduces supply-chain drift.",
					Fix:         "Pin the action to a trusted full commit SHA and use an update process such as Dependabot to keep it current.",
				})
			}
		}
		f.Close()
	}
}

func checkCompose(root string, res *Result) {
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		path := filepath.Join(root, name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(b)
		if regexp.MustCompile(`(?mi)^\s*privileged:\s*true\s*$`).MatchString(text) {
			res.Findings = append(res.Findings, Finding{
				ID: "COMPOSE_PRIVILEGED", Severity: High, Title: "Privileged container enabled", File: name,
				Explanation: "Privileged containers receive broad host capabilities and substantially weaken container isolation.",
				Fix:         "Remove privileged: true and grant only the specific capabilities/devices the workload actually needs.",
			})
		}
		if regexp.MustCompile(`(?mi)^\s*-\s*/var/run/docker\.sock:/var/run/docker\.sock`).MatchString(text) {
			res.Findings = append(res.Findings, Finding{
				ID: "COMPOSE_DOCKER_SOCKET", Severity: High, Title: "Docker socket mounted into container", File: name,
				Explanation: "Access to the Docker daemon socket can effectively provide control over the host Docker environment.",
				Fix:         "Avoid mounting the Docker socket. If orchestration is required, use a narrowly scoped proxy or isolated mechanism.",
			})
		}
	}
}

func checkSensitiveFiles(root string, res *Result) {
	for _, name := range []string{"id_rsa", "id_ed25519", ".npmrc", ".pypirc"} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			res.Findings = append(res.Findings, Finding{
				ID: "SENSITIVE_FILE", Severity: Medium, Title: "Security-sensitive file present in project root", File: name,
				Explanation: "This file commonly contains credentials or private key material and deserves explicit review before publishing.",
				Fix:         "Verify that it contains no live credentials and ensure it is excluded from version control when appropriate.",
			})
		}
	}
}
