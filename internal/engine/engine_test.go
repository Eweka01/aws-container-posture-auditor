package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

// stubCheck is a test double for the Check interface.
type stubCheck struct {
	id       string
	name     string
	dim      engine.Dimension
	findings []engine.Finding
	err      error
}

func (s *stubCheck) ID() string                  { return s.id }
func (s *stubCheck) Name() string                { return s.name }
func (s *stubCheck) Dimension() engine.Dimension { return s.dim }
func (s *stubCheck) Run(_ context.Context, _ *engine.AWSClient) ([]engine.Finding, error) {
	return s.findings, s.err
}

func TestEngine_RunReturnsAllResults(t *testing.T) {
	eng := engine.New(nil) // nil client — stubs don't use it
	eng.Register(
		&stubCheck{id: "check.a", dim: engine.DimensionOps, findings: []engine.Finding{
			{CheckID: "check.a", Title: "Finding A"},
		}},
		&stubCheck{id: "check.b", dim: engine.DimensionSupplyChain, findings: []engine.Finding{
			{CheckID: "check.b", Title: "Finding B"},
			{CheckID: "check.b", Title: "Finding B2"},
		}},
	)

	results := eng.Run(context.Background())
	require.Len(t, results, 2)

	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}
	assert.Equal(t, 3, total)
}

func TestEngine_CheckErrorDoesNotStopOthers(t *testing.T) {
	eng := engine.New(nil)
	eng.Register(
		&stubCheck{id: "fail", dim: engine.DimensionOps, err: errors.New("aws error")},
		&stubCheck{id: "ok", dim: engine.DimensionOps, findings: []engine.Finding{{CheckID: "ok"}}},
	)

	results := eng.Run(context.Background())
	require.Len(t, results, 2)

	var errResult, okResult engine.Result
	for _, r := range results {
		if r.Check.ID() == "fail" {
			errResult = r
		} else {
			okResult = r
		}
	}
	assert.Error(t, errResult.Err)
	assert.Len(t, okResult.Findings, 1)
}
