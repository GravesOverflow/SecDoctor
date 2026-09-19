package report

import (
	"fmt"
	"strings"

	"secdoctor/internal/scan"
)

func Print(r scan.Result) {
	fmt.Println("╭──────────────────────────────────────────────────────────╮")
	fmt.Println("│  🩺 SecDoctor — project security checkup                 │")
	fmt.Println("╰──────────────────────────────────────────────────────────╯")
	fmt.Printf("\nProject: %s\n", r.Root)
	fmt.Printf("Scanned: %d files · %s · fingerprint %s\n", r.Files, humanBytes(r.Bytes), r.Fingerprint)
	if r.Packages > 0 {
		fmt.Printf("Dependencies: %d checked · %d known vulnerabilities found\n", r.Packages, r.Vulnerabilities)
	}
	for _, warning := range r.Warnings {
		fmt.Printf("Warning: %s\n", warning)
	}
	fmt.Println()

	if len(r.Findings) == 0 {
		fmt.Println("✓ No findings from the enabled checks.")
		fmt.Println("\nNote: this is a focused static check, not a guarantee that the project is vulnerability-free.")
		return
	}

	fmt.Printf("Found %d issue(s)\n\n", len(r.Findings))
	for i, f := range r.Findings {
		where := ""
		if f.File != "" {
			where = "  " + f.File
			if f.Line > 0 {
				where += fmt.Sprintf(":%d", f.Line)
			}
		}
		fmt.Printf("%d. [%s] %s%s\n", i+1, f.Severity, f.Title, where)
		fmt.Printf("   Why: %s\n", f.Explanation)
		fmt.Printf("   Fix: %s\n", f.Fix)
		if f.Evidence != "" {
			fmt.Printf("   Evidence: %s\n", f.Evidence)
		}
		fmt.Println()
	}
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Completed in %s. Run `secdoctor explain .` for optional AI analysis.\n", fmt.Sprintf("%dms", r.DurationMS))
}

func humanBytes(n int64) string {
	const kb = 1024
	if n < kb {
		return fmt.Sprintf("%d B", n)
	}
	if n < kb*kb {
		return fmt.Sprintf("%.1f KB", float64(n)/kb)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(kb*kb))
}
