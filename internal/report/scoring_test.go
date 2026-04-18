package report_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
	"github.com/Eweka01/aws-container-posture-auditor/internal/report"
)

func TestScoring_CriticalPenalty(t *testing.T) {
	results := []engine.Result{
		{
			Check: &stubCheck{id: "x", dim: engine.DimensionOps},
			Findings: []engine.Finding{
				{Severity: engine.SeverityCritical, Dimension: engine.DimensionOps},
			},
		},
	}
	r := report.Build(results, "", "us-east-1", time.Second)
	assert.Equal(t, 80, r.Score.Overall) // 100 - 20 (critical weight)
	assert.Equal(t, 80, r.Score.OpsScore)
	assert.Equal(t, 100, r.Score.SupplyChain) // no SC findings
}

func TestScoring_ScoreNeverBelowZero(t *testing.T) {
	findings := make([]engine.Finding, 20)
	for i := range findings {
		findings[i] = engine.Finding{Severity: engine.SeverityCritical, Dimension: engine.DimensionOps}
	}
	results := []engine.Result{
		{Check: &stubCheck{id: "x", dim: engine.DimensionOps}, Findings: findings},
	}
	r := report.Build(results, "", "us-east-1", time.Second)
	assert.Equal(t, 0, r.Score.Overall)
	assert.GreaterOrEqual(t, r.Score.Overall, 0)
}

func TestScoring_MixedSeverities(t *testing.T) {
	results := []engine.Result{
		{
			Check: &stubCheck{id: "a", dim: engine.DimensionOps},
			Findings: []engine.Finding{
				{Severity: engine.SeverityHigh, Dimension: engine.DimensionOps},   // -10
				{Severity: engine.SeverityMedium, Dimension: engine.DimensionOps}, // -5
				{Severity: engine.SeverityLow, Dimension: engine.DimensionOps},    // -2
			},
		},
	}
	r := report.Build(results, "", "us-east-1", time.Second)
	assert.Equal(t, 83, r.Score.Overall) // 100 - 17
	assert.Equal(t, 1, r.Score.High)
	assert.Equal(t, 1, r.Score.Medium)
	assert.Equal(t, 1, r.Score.Low)
}

func TestFindingsByDimension(t *testing.T) {
	results := []engine.Result{
		{
			Check: &stubCheck{id: "ops", dim: engine.DimensionOps},
			Findings: []engine.Finding{
				{Severity: engine.SeverityHigh, Dimension: engine.DimensionOps},
			},
		},
		{
			Check: &stubCheck{id: "sc", dim: engine.DimensionSupplyChain},
			Findings: []engine.Finding{
				{Severity: engine.SeverityMedium, Dimension: engine.DimensionSupplyChain},
				{Severity: engine.SeverityMedium, Dimension: engine.DimensionSupplyChain},
			},
		},
	}
	r := report.Build(results, "", "us-east-1", time.Second)
	assert.Len(t, r.FindingsByDimension(engine.DimensionOps), 1)
	assert.Len(t, r.FindingsByDimension(engine.DimensionSupplyChain), 2)
}
