package report

import (
	"time"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

const Version = "0.1.0"

type Report struct {
	Version      string           `json:"version"`
	Timestamp    time.Time        `json:"timestamp"`
	AccountID    string           `json:"account_id"`
	Region       string           `json:"region"`
	ScanDuration time.Duration    `json:"scan_duration_ms"`
	Findings     []engine.Finding `json:"findings"`
	Score        ScoreCard        `json:"score"`
	ChecksRun    int              `json:"checks_run"`
	ChecksFailed int              `json:"checks_failed"`
}

type ScoreCard struct {
	Overall     int `json:"overall"`
	OpsScore    int `json:"ops_reliability"`
	SupplyChain int `json:"supply_chain_trust"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
	Info        int `json:"info"`
}

var severityWeight = map[engine.Severity]int{
	engine.SeverityCritical: 20,
	engine.SeverityHigh:     10,
	engine.SeverityMedium:   5,
	engine.SeverityLow:      2,
	engine.SeverityInfo:     0,
}

// Build assembles a Report from engine results.
func Build(results []engine.Result, accountID, region string, duration time.Duration) *Report {
	r := &Report{
		Version:      Version,
		Timestamp:    time.Now().UTC(),
		AccountID:    accountID,
		Region:       region,
		ScanDuration: duration,
	}

	var totalPenalty, opsPenalty, scPenalty int
	var opsChecks, scChecks int

	for _, res := range results {
		r.ChecksRun++
		if res.Err != nil {
			r.ChecksFailed++
		}
		for _, f := range res.Findings {
			r.Findings = append(r.Findings, f)
			w := severityWeight[f.Severity]
			totalPenalty += w
			switch f.Severity {
			case engine.SeverityCritical:
				r.Score.Critical++
			case engine.SeverityHigh:
				r.Score.High++
			case engine.SeverityMedium:
				r.Score.Medium++
			case engine.SeverityLow:
				r.Score.Low++
			case engine.SeverityInfo:
				r.Score.Info++
			}
			if f.Dimension == engine.DimensionOps {
				opsPenalty += w
			} else {
				scPenalty += w
			}
		}
		if res.Check != nil {
			if res.Check.Dimension() == engine.DimensionOps {
				opsChecks++
			} else {
				scChecks++
			}
		}
	}

	r.Score.Overall = clampScore(100 - totalPenalty)
	r.Score.OpsScore = clampScore(100 - opsPenalty)
	r.Score.SupplyChain = clampScore(100 - scPenalty)

	return r
}

func clampScore(s int) int {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

// TopCritical returns up to n critical/high findings for executive summary.
func (r *Report) TopCritical(n int) []engine.Finding {
	var out []engine.Finding
	for _, f := range r.Findings {
		if f.Severity == engine.SeverityCritical {
			out = append(out, f)
		}
		if len(out) >= n {
			return out
		}
	}
	for _, f := range r.Findings {
		if f.Severity == engine.SeverityHigh && len(out) < n {
			out = append(out, f)
		}
	}
	return out
}

// FindingsByDimension returns findings filtered by dimension.
func (r *Report) FindingsByDimension(dim engine.Dimension) []engine.Finding {
	var out []engine.Finding
	for _, f := range r.Findings {
		if f.Dimension == dim {
			out = append(out, f)
		}
	}
	return out
}
