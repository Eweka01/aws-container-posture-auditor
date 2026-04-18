package report

import (
	"html/template"
	"io"
	"time"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

type htmlData struct {
	Report      *Report
	ScanDate    string
	Duration    string
	OpsFindings []engine.Finding
	SCFindings  []engine.Finding
	TopFindings []engine.Finding
}

func RenderHTML(r *Report, w io.Writer) error {
	data := htmlData{
		Report:      r,
		ScanDate:    r.Timestamp.Format(time.RFC1123),
		Duration:    r.ScanDuration.Round(time.Millisecond).String(),
		OpsFindings: r.FindingsByDimension(engine.DimensionOps),
		SCFindings:  r.FindingsByDimension(engine.DimensionSupplyChain),
		TopFindings: r.TopCritical(3),
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": func(s engine.Severity) string {
			switch s {
			case engine.SeverityCritical:
				return "sev-critical"
			case engine.SeverityHigh:
				return "sev-high"
			case engine.SeverityMedium:
				return "sev-medium"
			case engine.SeverityLow:
				return "sev-low"
			default:
				return "sev-info"
			}
		},
		"scoreClass": func(score int) string {
			switch {
			case score >= 80:
				return "score-good"
			case score >= 60:
				return "score-warn"
			default:
				return "score-bad"
			}
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Container Posture Report</title>
<style>
:root {
  --bg: #f8f9fa; --surface: #ffffff; --border: #dee2e6;
  --text: #212529; --muted: #6c757d;
  --critical: #dc3545; --high: #fd7e14; --medium: #ffc107;
  --low: #0d6efd; --info: #6c757d;
  --good: #198754; --warn: #ffc107; --bad: #dc3545;
  --max-width: 1200px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1d21; --surface: #212529; --border: #495057;
    --text: #f8f9fa; --muted: #adb5bd;
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: var(--max-width); margin: 0 auto; padding: 2rem 1.5rem; }
header { border-bottom: 2px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
header h1 { font-size: 1.75rem; font-weight: 700; }
header .meta { color: var(--muted); font-size: 0.9rem; margin-top: 0.5rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
h2 { font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; }
h3 { font-size: 1rem; font-weight: 600; margin-bottom: 0.5rem; }
.score-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; }
.score-box { text-align: center; }
.score-number { font-size: 3.5rem; font-weight: 800; line-height: 1; }
.score-label { color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }
.score-good { color: var(--good); }
.score-warn { color: var(--warn); }
.score-bad  { color: var(--bad); }
.score-bar-wrap { margin-top: 1rem; }
.score-bar-label { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 4px; }
.score-bar-track { background: var(--border); border-radius: 4px; height: 10px; }
.score-bar-fill { height: 10px; border-radius: 4px; background: var(--good); }
.severity-counts { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 1rem; text-align: center; }
.sev-box { padding: 1rem; border-radius: 6px; border: 1px solid var(--border); }
.sev-count { font-size: 2rem; font-weight: 700; }
.sev-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
.sev-critical .sev-count { color: var(--critical); }
.sev-high    .sev-count { color: var(--high); }
.sev-medium  .sev-count { color: var(--medium); }
.sev-low     .sev-count { color: var(--low); }
.finding { border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem; border-left: 4px solid var(--border); }
.finding.sev-critical { border-left-color: var(--critical); }
.finding.sev-high     { border-left-color: var(--high); }
.finding.sev-medium   { border-left-color: var(--medium); }
.finding.sev-low      { border-left-color: var(--low); }
.finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
.badge { font-size: 0.7rem; font-weight: 700; padding: 2px 8px; border-radius: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.sev-critical .badge { background: var(--critical); color: #fff; }
.sev-high     .badge { background: var(--high); color: #fff; }
.sev-medium   .badge { background: var(--medium); color: #212529; }
.sev-low      .badge { background: var(--low); color: #fff; }
.finding-title { font-weight: 600; }
.check-id { font-size: 0.8rem; color: var(--muted); font-family: monospace; }
.resource { font-size: 0.8rem; color: var(--muted); font-family: monospace; word-break: break-all; margin: 0.25rem 0; }
.desc { font-size: 0.9rem; margin: 0.5rem 0; }
details { margin-top: 0.5rem; }
summary { cursor: pointer; font-size: 0.85rem; font-weight: 600; color: var(--muted); }
summary:hover { color: var(--text); }
pre { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.75rem; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; margin-top: 0.5rem; }
.refs { margin-top: 0.5rem; font-size: 0.8rem; }
.refs a { color: var(--low); }
.section-header { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; margin: 1.5rem 0 0.75rem; font-weight: 600; border-bottom: 1px solid var(--border); padding-bottom: 0.25rem; }
.compliance-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
.compliance-table th { text-align: left; padding: 0.5rem; background: var(--bg); border: 1px solid var(--border); }
.compliance-table td { padding: 0.5rem; border: 1px solid var(--border); }
footer { border-top: 1px solid var(--border); padding-top: 1rem; margin-top: 2rem; font-size: 0.8rem; color: var(--muted); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }
@media print { .card { break-inside: avoid; } }
</style>
</head>
<body>
<div class="container">

<header>
  <h1>AWS Container Posture Report</h1>
  <div class="meta">
    Account: <strong>{{.Report.AccountID}}</strong> &nbsp;|&nbsp;
    Region: <strong>{{.Report.Region}}</strong> &nbsp;|&nbsp;
    Scanned: <strong>{{.ScanDate}}</strong> &nbsp;|&nbsp;
    Tool: <strong>acpa v{{.Report.Version}}</strong>
  </div>
</header>

<div class="card">
  <h2>Executive Summary</h2>
  <div class="score-grid">
    <div class="score-box">
      <div class="score-number {{scoreClass .Report.Score.Overall}}">{{.Report.Score.Overall}}</div>
      <div class="score-label">Overall Posture Score / 100</div>
    </div>
    <div class="score-box">
      <div>
        <div class="score-bar-wrap">
          <div class="score-bar-label"><span>Operational Reliability</span><span>{{.Report.Score.OpsScore}}/100</span></div>
          <div class="score-bar-track"><div class="score-bar-fill" style="width:{{.Report.Score.OpsScore}}%"></div></div>
        </div>
        <div class="score-bar-wrap" style="margin-top:1rem">
          <div class="score-bar-label"><span>Supply Chain Trust</span><span>{{.Report.Score.SupplyChain}}/100</span></div>
          <div class="score-bar-track"><div class="score-bar-fill" style="width:{{.Report.Score.SupplyChain}}%"></div></div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="card">
  <h2>Findings by Severity</h2>
  <div class="severity-counts">
    <div class="sev-box sev-critical"><div class="sev-count">{{.Report.Score.Critical}}</div><div class="sev-label">Critical</div></div>
    <div class="sev-box sev-high"><div class="sev-count">{{.Report.Score.High}}</div><div class="sev-label">High</div></div>
    <div class="sev-box sev-medium"><div class="sev-count">{{.Report.Score.Medium}}</div><div class="sev-label">Medium</div></div>
    <div class="sev-box sev-low"><div class="sev-count">{{.Report.Score.Low}}</div><div class="sev-label">Low</div></div>
  </div>

  {{if .TopFindings}}
  <div style="margin-top:1.5rem">
    <h3>Top Priority Findings</h3>
    {{range $i, $f := .TopFindings}}
    <div class="finding {{severityClass $f.Severity}}">
      <div class="finding-header">
        <span class="badge">{{$f.Severity}}</span>
        <span class="finding-title">{{$f.Title}}</span>
      </div>
      <div class="check-id">{{$f.CheckID}}</div>
      {{if $f.Resource}}<div class="resource">{{$f.Resource}}</div>{{end}}
    </div>
    {{end}}
  </div>
  {{end}}
</div>

{{if .OpsFindings}}
<div class="card">
  <h2>Operational Reliability Findings</h2>
  {{range .OpsFindings}}
  <div class="finding {{severityClass .Severity}}">
    <div class="finding-header">
      <span class="badge">{{.Severity}}</span>
      <span class="finding-title">{{.Title}}</span>
    </div>
    <div class="check-id">{{.CheckID}}</div>
    {{if .Resource}}<div class="resource">{{.Resource}}</div>{{end}}
    <div class="desc">{{.Description}}</div>
    <details>
      <summary>Remediation</summary>
      <pre>{{.Remediation}}</pre>
      {{if .References}}<div class="refs">References: {{range .References}}<a href="{{.}}" target="_blank" rel="noopener">{{.}}</a> {{end}}</div>{{end}}
    </details>
  </div>
  {{end}}
</div>
{{end}}

{{if .SCFindings}}
<div class="card">
  <h2>Supply Chain Trust Findings</h2>
  {{range .SCFindings}}
  <div class="finding {{severityClass .Severity}}">
    <div class="finding-header">
      <span class="badge">{{.Severity}}</span>
      <span class="finding-title">{{.Title}}</span>
    </div>
    <div class="check-id">{{.CheckID}}</div>
    {{if .Resource}}<div class="resource">{{.Resource}}</div>{{end}}
    <div class="desc">{{.Description}}</div>
    <details>
      <summary>Remediation</summary>
      <pre>{{.Remediation}}</pre>
      {{if .References}}<div class="refs">References: {{range .References}}<a href="{{.}}" target="_blank" rel="noopener">{{.}}</a> {{end}}</div>{{end}}
    </details>
  </div>
  {{end}}
</div>
{{end}}

<div class="card">
  <h2>Compliance Mapping</h2>
  <table class="compliance-table">
    <thead>
      <tr><th>Check ID</th><th>Framework</th><th>Control</th></tr>
    </thead>
    <tbody>
      <tr><td>ops.eks.outdated_version</td><td>CIS AWS Foundations</td><td>5.4 — EKS version</td></tr>
      <tr><td>ops.eks.public_endpoint</td><td>AWS Well-Architected (Reliability)</td><td>Network access control</td></tr>
      <tr><td>ops.eks.no_logging</td><td>NIST SP 800-53</td><td>AU-2 — Event logging</td></tr>
      <tr><td>ops.ecs.no_health_check</td><td>AWS Well-Architected (Reliability)</td><td>REL 6 — Monitor health</td></tr>
      <tr><td>ops.obs.no_log_retention</td><td>AWS Well-Architected (OE)</td><td>OPS 7 — Workload health</td></tr>
      <tr><td>sc.ecr.scan_disabled</td><td>NIST SSDF (SP 800-218)</td><td>RV.1 — Vulnerability scanning</td></tr>
      <tr><td>sc.ecr.unsigned_images</td><td>SLSA Level 2</td><td>Provenance — build integrity</td></tr>
      <tr><td>sc.img.mutable_tags</td><td>SLSA Level 2</td><td>Provenance — artifact integrity</td></tr>
      <tr><td>sc.ecr.no_sbom</td><td>NIST SSDF (SP 800-218)</td><td>PW.4 — SBOM generation</td></tr>
      <tr><td>sc.eks.no_admission_controller</td><td>CIS Software Supply Chain</td><td>Deploy-time verification</td></tr>
      <tr><td>sc.lambda.no_code_signing</td><td>NIST SSDF (SP 800-218)</td><td>PO.3 — Code signing</td></tr>
      <tr><td>ops.lambda.deprecated_runtime</td><td>AWS Well-Architected (Security)</td><td>SEC 10 — Patch management</td></tr>
    </tbody>
  </table>
</div>

<footer>
  <span>Generated by acpa v{{.Report.Version}} &mdash; <a href="https://github.com/Eweka01/aws-container-posture-auditor">github.com/Eweka01/aws-container-posture-auditor</a></span>
  <span>Scan duration: {{.Duration}} &nbsp;|&nbsp; Checks run: {{.Report.ChecksRun}} &nbsp;|&nbsp; Total findings: {{len .Report.Findings}}</span>
</footer>

</div>
</body>
</html>`
