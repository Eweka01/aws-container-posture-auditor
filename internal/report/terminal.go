package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

func RenderTerminal(r *Report, w io.Writer) {
	fmt.Fprintf(w, "\nAWS Container Posture Auditor v%s\n", r.Version)
	fmt.Fprintf(w, "Scanning region: %s\n", r.Region)
	if r.AccountID != "" {
		fmt.Fprintf(w, "Account ID: %s\n", r.AccountID)
	}
	fmt.Fprintf(w, "\n[✓] Scan completed (%d checks, %d findings)\n", r.ChecksRun, len(r.Findings))
	if r.ChecksFailed > 0 {
		fmt.Fprintf(w, "[!] %d check(s) encountered errors\n", r.ChecksFailed)
	}

	sep := strings.Repeat("─", 60)
	fmt.Fprintf(w, "\n%s\n", sep)
	fmt.Fprintf(w, "POSTURE SCORE: %d / 100\n", r.Score.Overall)
	fmt.Fprintf(w, "%s\n\n", sep)

	fmt.Fprintf(w, "Breakdown:\n")
	fmt.Fprintf(w, "  Operational Reliability:    %d / 100\n", r.Score.OpsScore)
	fmt.Fprintf(w, "  Supply Chain Trust:         %d / 100\n\n", r.Score.SupplyChain)

	fmt.Fprintf(w, "Findings by severity:\n")
	fmt.Fprintf(w, "  Critical:  %3d\n", r.Score.Critical)
	fmt.Fprintf(w, "  High:      %3d\n", r.Score.High)
	fmt.Fprintf(w, "  Medium:    %3d\n", r.Score.Medium)
	fmt.Fprintf(w, "  Low:       %3d\n\n", r.Score.Low)

	top := r.TopCritical(3)
	if len(top) > 0 {
		fmt.Fprintf(w, "Top critical/high findings:\n")
		for i, f := range top {
			fmt.Fprintf(w, "  %d. [%s] %s\n", i+1, f.CheckID, f.Title)
			if f.Resource != "" {
				fmt.Fprintf(w, "     Resource: %s\n", f.Resource)
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.Findings) > 0 {
		fmt.Fprintf(w, "All findings:\n")
		for _, f := range r.Findings {
			badge := severityBadge(f.Severity)
			fmt.Fprintf(w, "  %s [%s] %s\n", badge, f.CheckID, f.Title)
			if f.Resource != "" {
				fmt.Fprintf(w, "     → %s\n", f.Resource)
			}
		}
		fmt.Fprintln(w)
	}
}

func severityBadge(s engine.Severity) string {
	switch s {
	case engine.SeverityCritical:
		return "[CRITICAL]"
	case engine.SeverityHigh:
		return "[HIGH    ]"
	case engine.SeverityMedium:
		return "[MEDIUM  ]"
	case engine.SeverityLow:
		return "[LOW     ]"
	default:
		return "[INFO    ]"
	}
}
