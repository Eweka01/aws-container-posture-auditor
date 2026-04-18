# AWS Container Posture Auditor (`acpa`)

A free, open-source CLI that scans your AWS account **read-only** and produces an executive-readable posture report across two dimensions: **operational reliability** and **supply chain trust**.

> **No data leaves your machine.** The binary runs entirely locally, uses the standard AWS credential chain, and never stores or transmits your credentials.

---

## Why this tool exists

DevOps and platform teams manage AWS container workloads every day but rarely audit their own posture comprehensively. Existing tools focus narrowly on security (Prowler, ScoutSuite), narrowly on Kubernetes (kube-bench, kubescape), or are commercial SaaS with enterprise pricing.

`acpa` fills the gap: a **free, AWS-native, container-focused, dual-dimension CLI** that produces output an executive can read and a consultant can hand to a client.

Post-SolarWinds and post-Log4j, supply chain trust is a board-level concern. Operational reliability always has been. This tool surfaces both in a single assessment.

---

## Sample report

See [`examples/sample-report/posture-report.html`](examples/sample-report/posture-report.html) for an example of the HTML output without running anything.

---

## Installation

### Homebrew (macOS / Linux)
```bash
brew install Eweka01/tap/acpa
```

### Go install
```bash
go install github.com/Eweka01/aws-container-posture-auditor/cmd/acpa@latest
```

### Direct download
```bash
curl -L https://github.com/Eweka01/aws-container-posture-auditor/releases/latest/download/acpa-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o acpa
chmod +x acpa
```

---

## Quick start

```bash
# 1. Attach the minimal IAM policy to your role/user (see docs/iam-policy.json)
acpa iam-policy > /tmp/acpa-policy.json
aws iam create-policy --policy-name ACPAReadOnly --policy-document file:///tmp/acpa-policy.json

# 2. Run a full scan
acpa scan

# 3. Open the HTML report
open ./posture-report/posture-report.html
```

---

## Usage

```bash
# Full scan (current region, all outputs)
acpa scan

# Specific region and profile
acpa scan --region us-east-1 --profile production

# Only the supply chain engine
acpa scan --engine supplychain

# HTML only, custom output directory
acpa scan --output html --output-dir /tmp/audit

# List all available checks
acpa checks list

# Show details of a check
acpa checks info ops.ecs.no_autoscaling

# Print the required IAM policy
acpa iam-policy
```

See [`docs/usage.md`](docs/usage.md) for the full CLI reference.

---

## What it checks

### Operational Reliability (19 checks)
| Area | Checks |
|---|---|
| ECS / Fargate | Auto-scaling, health checks, `:latest` tags, logging, circuit breaker, HA task count |
| EKS | Kubernetes version EOL, managed add-ons, public API endpoint, control plane logging, single-AZ node groups |
| Lambda | Dead-letter queues, deprecated runtimes, X-Ray tracing, reserved concurrency |
| Observability | CloudWatch log retention, alarms on critical resources, Container Insights |

### Supply Chain Trust (11 checks)
| Area | Checks |
|---|---|
| ECR Signing | Cosign signatures, SBOM OCI referrers, scan-on-push, lifecycle policies |
| Image Policy | Tag immutability, digest pinning in deployments, `:latest` in production |
| EKS Admission | Admission controller presence, image signature verification policy |
| Lambda Signing | AWS Signer configuration, enforcement mode |

See [`docs/check-catalog.md`](docs/check-catalog.md) for full details.

---

## Required IAM permissions

A minimal read-only policy is documented in [`docs/iam-policy.json`](docs/iam-policy.json) and printable with `acpa iam-policy`. It never requires write permissions or wildcard actions beyond the scoped list.

---

## Report formats

| Format | Description |
|---|---|
| **HTML** | Primary output — consultant-grade, self-contained, dark mode, print-friendly |
| **JSON** | Machine-readable, suitable for CI gates and dashboards |
| **CSV** | Spreadsheet-friendly for tracking and ticket creation |
| **Terminal** | Inline summary with severity counts and top findings |

---

## Design principles

1. **Local-first.** No server, no backend, no phone-home.
2. **Zero custom auth.** Standard AWS credential chain only.
3. **Least privilege.** Scoped read-only IAM policy.
4. **Stateless.** No database. Every run is fresh.
5. **Deterministic.** No LLM calls in scanning logic.
6. **Read-only.** Never modifies customer infrastructure.

---

## Compliance mapping

| Dimension | Frameworks |
|---|---|
| Operational Reliability | AWS Well-Architected (Reliability + OE), CIS AWS Foundations |
| Supply Chain Trust | SLSA, NIST SSDF (SP 800-218), CIS Software Supply Chain, Sigstore/Cosign, OpenSSF Scorecard |

Reports are suitable as SOC 2 and ISO 27001 evidence.

---

## Roadmap (out of v1 scope)

- `--ai-summary` flag using AWS Bedrock for LLM-generated executive narrative
- Multi-account scanning via assume-role
- SNS/SQS posture checks
- Historical trend tracking

**Not on the roadmap:** auto-remediation (violates read-only principle), web dashboard (violates local-first principle).

---

## Contributing

Adding a new check takes less than 30 minutes. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for a step-by-step guide.

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
