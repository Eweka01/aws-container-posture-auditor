package report_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
	"github.com/Eweka01/aws-container-posture-auditor/internal/report"
)

func fixedResults() []engine.Result {
	return []engine.Result{
		{
			Check: &stubCheck{id: "ops.ecs.no_autoscaling", dim: engine.DimensionOps},
			Findings: []engine.Finding{
				{CheckID: "ops.ecs.no_autoscaling", Severity: engine.SeverityCritical, Dimension: engine.DimensionOps, Title: "No autoscaling"},
				{CheckID: "ops.ecs.no_autoscaling", Severity: engine.SeverityHigh, Dimension: engine.DimensionOps, Title: "No autoscaling"},
			},
		},
		{
			Check: &stubCheck{id: "sc.ecr.scan_disabled", dim: engine.DimensionSupplyChain},
			Findings: []engine.Finding{
				{CheckID: "sc.ecr.scan_disabled", Severity: engine.SeverityHigh, Dimension: engine.DimensionSupplyChain, Title: "Scan disabled"},
			},
		},
	}
}

type stubCheck struct {
	id  string
	dim engine.Dimension
}

func (s *stubCheck) ID() string                 { return s.id }
func (s *stubCheck) Name() string               { return s.id }
func (s *stubCheck) Dimension() engine.Dimension { return s.dim }
func (s *stubCheck) Run(_ context.Context, _ *engine.AWSClient) ([]engine.Finding, error) {
	return nil, nil
}

func TestBuild_ScoresClampedTo100(t *testing.T) {
	r := report.Build(fixedResults(), "123456789", "us-east-1", time.Second)
	assert.GreaterOrEqual(t, r.Score.Overall, 0)
	assert.LessOrEqual(t, r.Score.Overall, 100)
	assert.Equal(t, 1, r.Score.Critical)
	assert.Equal(t, 2, r.Score.High)
}

func TestBuild_FindingCountsMatchInput(t *testing.T) {
	r := report.Build(fixedResults(), "123456789", "us-east-1", time.Second)
	assert.Len(t, r.Findings, 3)
	assert.Equal(t, 2, r.ChecksRun)
}

func TestRenderJSON_ValidJSON(t *testing.T) {
	r := report.Build(fixedResults(), "123456789", "us-east-1", time.Second)
	var buf bytes.Buffer
	err := report.RenderJSON(r, &buf)
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, "us-east-1", decoded["region"])
}

func TestRenderCSV_HasHeader(t *testing.T) {
	r := report.Build(fixedResults(), "123456789", "us-east-1", time.Second)
	var buf bytes.Buffer
	err := report.RenderCSV(r, &buf)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(buf.String(), "check_id,"))
}

func TestRenderHTML_ContainsTitle(t *testing.T) {
	r := report.Build(fixedResults(), "123456789", "us-east-1", time.Second)
	var buf bytes.Buffer
	err := report.RenderHTML(r, &buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "AWS Container Posture Report")
	assert.Contains(t, buf.String(), "123456789")
}

func TestRenderTerminal_ContainsScore(t *testing.T) {
	r := report.Build(fixedResults(), "123456789", "us-east-1", time.Second)
	var buf bytes.Buffer
	report.RenderTerminal(r, &buf)
	assert.Contains(t, buf.String(), "POSTURE SCORE")
}

func TestTopCritical_ReturnsAtMostN(t *testing.T) {
	r := report.Build(fixedResults(), "123456789", "us-east-1", time.Second)
	top := r.TopCritical(2)
	assert.LessOrEqual(t, len(top), 2)
}
