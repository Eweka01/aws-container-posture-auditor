package engine

import (
	"context"
	"log/slog"
	"sync"
)

type Result struct {
	Check    Check
	Findings []Finding
	Err      error
}

type Engine struct {
	checks []Check
	client *AWSClient
}

func New(client *AWSClient) *Engine {
	return &Engine{client: client}
}

func (e *Engine) Register(checks ...Check) {
	e.checks = append(e.checks, checks...)
}

func (e *Engine) Run(ctx context.Context) []Result {
	results := make([]Result, len(e.checks))
	var wg sync.WaitGroup

	for i, check := range e.checks {
		wg.Add(1)
		go func(idx int, c Check) {
			defer wg.Done()
			findings, err := c.Run(ctx, e.client)
			if err != nil {
				slog.Warn("check failed", "check_id", c.ID(), "error", err)
			}
			results[idx] = Result{Check: c, Findings: findings, Err: err}
		}(i, check)
	}

	wg.Wait()
	return results
}

func (e *Engine) RunByDimension(ctx context.Context, dim Dimension) []Result {
	var filtered []Check
	for _, c := range e.checks {
		if c.Dimension() == dim {
			filtered = append(filtered, c)
		}
	}
	orig := e.checks
	e.checks = filtered
	results := e.Run(ctx)
	e.checks = orig
	return results
}
