package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"secdoctor/internal/audit"
	"secdoctor/internal/remediate"
	"secdoctor/internal/report"
)

const version = "1.0.0-rc3"

//go:embed web/*
var assets embed.FS

func main() {
	root, err := fs.Sub(assets, "web")
	fatal(err)
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(root)))
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		write(w, 200, map[string]string{"status": "ok", "version": version})
	})
	mux.HandleFunc("/api/audit", runAudit)
	mux.HandleFunc("/api/fix/plan", fixPlan)
	mux.HandleFunc("/api/fix/lab", fixLab)
	mux.HandleFunc("/api/fix/proof", fixProof)
	mux.HandleFunc("/api/fix/apply", fixApply)
	mux.HandleFunc("/api/fix/rollback", fixRollback)
	mux.HandleFunc("/api/report/export", exportReport)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	fatal(err)
	token, err := newSessionToken()
	fatal(err)
	origin := "http://" + ln.Addr().String()
	url := origin + "/#session=" + token
	fmt.Printf("SecDoctor Desktop %s\n%s\n", version, origin)
	go func() { time.Sleep(250 * time.Millisecond); _ = open(url) }()
	fatal(http.Serve(ln, headers(sessionGuard(mux, origin, token))))
}
func runAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		write(w, 405, map[string]string{"error": "POST required"})
		return
	}
	var q struct {
		Path    string `json:"path"`
		Offline bool   `json:"offline"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		write(w, 400, map[string]string{"error": "Invalid request"})
		return
	}
	if q.Path == "" {
		q.Path = "."
	}
	root, err := filepath.Abs(q.Path)
	if err != nil {
		write(w, 400, map[string]string{"error": err.Error()})
		return
	}
	i, err := os.Stat(root)
	if err != nil || !i.IsDir() {
		write(w, 400, map[string]string{"error": "Project directory not found"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, err := audit.Run(ctx, root, q.Offline)
	if err != nil {
		write(w, 500, map[string]string{"error": err.Error()})
		return
	}
	write(w, 200, result)
}
func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func sessionGuard(next http.Handler, origin, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin {
				write(w, http.StatusForbidden, map[string]string{"error": "Invalid Origin"})
				return
			}
			got := r.Header.Get("X-SecDoctor-Session")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				write(w, http.StatusUnauthorized, map[string]string{"error": "Missing or invalid SecDoctor session"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func headers(n http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:")
		n.ServeHTTP(w, r)
	})
}
func write(w http.ResponseWriter, s int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(s)
	_ = json.NewEncoder(w).Encode(v)
}
func open(u string) error {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	} else if runtime.GOOS == "darwin" {
		c = exec.Command("open", u)
	} else {
		c = exec.Command("xdg-open", u)
	}
	return c.Start()
}
func fatal(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, "secdoctor:", e)
		os.Exit(1)
	}
}

func fixPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		write(w, 405, map[string]string{"error": "POST required"})
		return
	}
	var q struct {
		Path  string            `json:"path"`
		Fixes map[string]string `json:"fixes"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		write(w, 400, map[string]string{"error": "Invalid request"})
		return
	}
	root, e := filepath.Abs(q.Path)
	if e != nil {
		write(w, 400, map[string]string{"error": e.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	p, e := remediate.PlanNPM(ctx, root, q.Fixes)
	if e != nil {
		write(w, 400, map[string]string{"error": e.Error()})
		return
	}
	write(w, 200, p)
}
func fixApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		write(w, 405, map[string]string{"error": "POST required"})
		return
	}
	var q struct {
		PlanID      string `json:"plan_id"`
		SyncRuntime bool   `json:"sync_runtime"`
		RunTests    bool   `json:"run_tests"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		write(w, 400, map[string]string{"error": "Invalid request"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	applied, e := remediate.ApplyVerified(ctx, q.PlanID, q.SyncRuntime, q.RunTests)
	if e != nil {
		write(w, 500, map[string]string{"error": e.Error()})
		return
	}
	write(w, 200, applied)
}
func fixRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		write(w, 405, map[string]string{"error": "POST required"})
		return
	}
	var q struct {
		PlanID      string `json:"plan_id"`
		SyncRuntime bool   `json:"sync_runtime"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		write(w, 400, map[string]string{"error": "Invalid request"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	result, e := remediate.Rollback(ctx, q.PlanID, q.SyncRuntime)
	if e != nil {
		write(w, 500, map[string]any{"error": e.Error(), "rollback": result})
		return
	}
	write(w, 200, result)
}

func fixLab(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		write(w, 405, map[string]string{"error": "POST required"})
		return
	}
	var q struct {
		PlanID   string `json:"plan_id"`
		RunTests bool   `json:"run_tests"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		write(w, 400, map[string]string{"error": "Invalid request"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	proof, e := remediate.VerifyLab(ctx, q.PlanID, q.RunTests)
	if e != nil {
		write(w, 500, map[string]any{"error": e.Error(), "proof": proof})
		return
	}
	write(w, 200, proof)
}
func fixProof(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	proof, e := remediate.Proof(id)
	if e != nil {
		write(w, 404, map[string]string{"error": e.Error()})
		return
	}
	if e = remediate.VerifyProofSignature(proof); e != nil {
		write(w, 409, map[string]string{"error": e.Error()})
		return
	}
	write(w, 200, map[string]any{"verified": true, "proof": proof})
}

func exportReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		write(w, 405, map[string]string{"error": "POST required"})
		return
	}
	var q struct {
		Path   string `json:"path"`
		PlanID string `json:"plan_id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		write(w, 400, map[string]string{"error": "Invalid request"})
		return
	}
	if strings.TrimSpace(q.Path) == "" {
		q.Path = "."
	}
	root, err := filepath.Abs(q.Path)
	if err != nil {
		write(w, 400, map[string]string{"error": err.Error()})
		return
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		write(w, 400, map[string]string{"error": "Project directory not found"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	a, err := audit.Run(ctx, root, false)
	if err != nil {
		write(w, 500, map[string]string{"error": err.Error()})
		return
	}

	var proof *remediate.LabProof
	proofVerified := false
	if q.PlanID != "" {
		p, proofErr := remediate.Proof(q.PlanID)
		if proofErr != nil {
			write(w, 400, map[string]string{"error": "Remediation proof not found"})
			return
		}
		if p.Project != root {
			write(w, 409, map[string]string{"error": "Remediation proof belongs to a different project"})
			return
		}
		proof = &p
		proofVerified = remediate.VerifyProofSignature(p) == nil
	}
	rep := report.Build(a, version, proof, proofVerified)
	j, err := report.JSON(rep)
	if err != nil {
		write(w, 500, map[string]string{"error": err.Error()})
		return
	}
	write(w, 200, map[string]string{
		"markdown_filename": report.Filename(rep.Project, "md"),
		"markdown":          string(report.Markdown(rep)),
		"json_filename":     report.Filename(rep.Project, "json"),
		"json":              string(j) + "\n",
	})
}
