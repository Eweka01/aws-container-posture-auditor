package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	awsclient "github.com/Eweka01/aws-container-posture-auditor/internal/aws"
	"github.com/Eweka01/aws-container-posture-auditor/internal/checks/ops"
	"github.com/Eweka01/aws-container-posture-auditor/internal/checks/supplychain"
	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
	"github.com/Eweka01/aws-container-posture-auditor/internal/report"
)

var version = "0.1.0"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "acpa",
		Short: "AWS Container Posture Auditor — free, read-only AWS container posture scanning",
		Long: `acpa scans your AWS account read-only and produces an executive-readable
posture report covering operational reliability and supply chain trust.

No data leaves your machine. No credentials are stored or logged.`,
	}

	root.AddCommand(
		newScanCmd(),
		newChecksCmd(),
		newIAMPolicyCmd(),
		newVersionCmd(),
	)
	return root
}

// ── scan ──────────────────────────────────────────────────────────────────────

type scanFlags struct {
	region      string
	profile     string
	engineArg   string
	checkFilter string
	outputFmt   string
	outputDir   string
}

func newScanCmd() *cobra.Command {
	f := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a posture scan against your AWS account",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), f)
		},
	}

	cmd.Flags().StringVar(&f.region, "region", "", "AWS region to scan (default: from config/env)")
	cmd.Flags().StringVar(&f.profile, "profile", "", "AWS named profile to use")
	cmd.Flags().StringVar(&f.engineArg, "engine", "", "Run only one engine: ops | supplychain")
	cmd.Flags().StringVar(&f.checkFilter, "check", "", "Run only checks whose ID starts with this prefix (e.g. sc.ecr)")
	cmd.Flags().StringVar(&f.outputFmt, "output", "", "Output format(s): terminal, json, csv, html (default: all)")
	cmd.Flags().StringVar(&f.outputDir, "output-dir", "./posture-report", "Directory to write report files")

	return cmd
}

func runScan(ctx context.Context, f *scanFlags) error {
	if f.region == "" {
		f.region = os.Getenv("AWS_DEFAULT_REGION")
		if f.region == "" {
			f.region = os.Getenv("AWS_REGION")
		}
		if f.region == "" {
			f.region = "us-east-1"
		}
	}

	client, err := awsclient.NewClient(ctx, f.region, f.profile)
	if err != nil {
		return fmt.Errorf("failed to initialize AWS client: %w", err)
	}

	eng := engine.New(client)

	var checks []engine.Check
	switch f.engineArg {
	case "ops":
		checks = opsChecks()
	case "supplychain", "supply-chain", "sc":
		checks = supplyChainChecks()
	default:
		checks = append(opsChecks(), supplyChainChecks()...)
	}

	if f.checkFilter != "" {
		var filtered []engine.Check
		for _, c := range checks {
			if strings.HasPrefix(c.ID(), f.checkFilter) {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}
	eng.Register(checks...)

	start := time.Now()
	results := eng.Run(ctx)
	duration := time.Since(start)

	r := report.Build(results, client.Account, f.region, duration)

	// Always print terminal summary
	report.RenderTerminal(r, os.Stdout)

	// Write file outputs
	fmts := f.outputFmt
	writeHTML := fmts == "" || fmts == "html"
	writeJSON := fmts == "" || fmts == "json"
	writeCSV := fmts == "" || fmts == "csv"

	if writeHTML || writeJSON || writeCSV {
		if err := os.MkdirAll(f.outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if writeJSON {
		if err := writeReport(f.outputDir, "posture-report.json", func(w *os.File) error {
			return report.RenderJSON(r, w)
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write JSON report: %v\n", err)
		}
	}

	if writeCSV {
		if err := writeReport(f.outputDir, "posture-report.csv", func(w *os.File) error {
			return report.RenderCSV(r, w)
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write CSV report: %v\n", err)
		}
	}

	if writeHTML {
		if err := writeReport(f.outputDir, "posture-report.html", func(w *os.File) error {
			return report.RenderHTML(r, w)
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write HTML report: %v\n", err)
		}
	}

	if writeHTML || writeJSON || writeCSV {
		fmt.Printf("Reports written to %s/\n", f.outputDir)
		if writeHTML {
			fmt.Printf("  • posture-report.html  (executive report — start here)\n")
		}
		if writeJSON {
			fmt.Printf("  • posture-report.json  (machine-readable)\n")
		}
		if writeCSV {
			fmt.Printf("  • posture-report.csv   (spreadsheet-friendly)\n")
		}
		fmt.Println()
	}

	return nil
}

func writeReport(dir, name string, fn func(*os.File) error) error {
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}

func opsChecks() []engine.Check {
	var c []engine.Check
	c = append(c, ops.ECSChecks()...)
	c = append(c, ops.EKSChecks()...)
	c = append(c, ops.LambdaChecks()...)
	c = append(c, ops.ObservabilityChecks()...)
	return c
}

func supplyChainChecks() []engine.Check {
	var c []engine.Check
	c = append(c, supplychain.ECRSigningChecks()...)
	c = append(c, supplychain.ImagePolicyChecks()...)
	c = append(c, supplychain.EKSAdmissionChecks()...)
	c = append(c, supplychain.LambdaSigningChecks()...)
	return c
}

// ── checks ────────────────────────────────────────────────────────────────────

func newChecksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "List and inspect available checks",
	}
	cmd.AddCommand(newChecksListCmd(), newChecksInfoCmd())
	return cmd
}

func newChecksListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all available checks",
		Run: func(cmd *cobra.Command, args []string) {
			all := allChecks()
			fmt.Printf("%-45s %-16s %-10s %s\n", "CHECK ID", "DIMENSION", "SEVERITY", "NAME")
			fmt.Printf("%-45s %-16s %-10s %s\n", "--------", "---------", "--------", "----")
			for _, c := range all {
				// Run a dummy context to get the check's severity if available
				// For list purposes we print IDs and names only
				fmt.Printf("%-45s %-16s %s\n", c.ID(), shortDim(c.Dimension()), c.Name())
			}
		},
	}
}

func newChecksInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <check-id>",
		Short: "Show details of a specific check",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := args[0]
			for _, c := range allChecks() {
				if c.ID() == id {
					fmt.Printf("ID:        %s\n", c.ID())
					fmt.Printf("Name:      %s\n", c.Name())
					fmt.Printf("Dimension: %s\n", c.Dimension())
					return
				}
			}
			fmt.Fprintf(os.Stderr, "Check %q not found. Run `acpa checks list` to see all checks.\n", id)
			os.Exit(1)
		},
	}
}

func allChecks() []engine.Check {
	return append(opsChecks(), supplyChainChecks()...)
}

func shortDim(d engine.Dimension) string {
	if d == engine.DimensionOps {
		return "ops"
	}
	return "supply-chain"
}

// ── iam-policy ────────────────────────────────────────────────────────────────

func newIAMPolicyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "iam-policy",
		Short: "Print the minimal read-only IAM policy required by acpa",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(iamPolicy)
		},
	}
}

const iamPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ACPAReadOnly",
      "Effect": "Allow",
      "Action": [
        "application-autoscaling:Describe*",
        "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
        "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
        "ecr:Describe*", "ecr:List*", "ecr:GetRepositoryPolicy",
        "ecr:GetLifecyclePolicy",
        "ecs:Describe*", "ecs:List*",
        "eks:Describe*", "eks:List*",
        "iam:Get*", "iam:List*",
        "lambda:Get*", "lambda:List*",
        "logs:Describe*", "logs:List*",
        "signer:Get*", "signer:List*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}`

// ── version ───────────────────────────────────────────────────────────────────

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("acpa v%s\n", version)
		},
	}
}
