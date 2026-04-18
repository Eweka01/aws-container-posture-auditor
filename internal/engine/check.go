package engine

import (
	"context"

	awsclient "github.com/Eweka01/aws-container-posture-auditor/internal/aws"
)

// AWSClient is a re-export alias for convenience in check implementations.
type AWSClient = awsclient.AWSClient

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Dimension string

const (
	DimensionOps         Dimension = "operational_reliability"
	DimensionSupplyChain Dimension = "supply_chain_trust"
)

type Finding struct {
	CheckID     string    `json:"check_id"`
	Dimension   Dimension `json:"dimension"`
	Severity    Severity  `json:"severity"`
	Resource    string    `json:"resource"`
	Region      string    `json:"region"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	References  []string  `json:"references,omitempty"`
}

type Check interface {
	ID() string
	Name() string
	Dimension() Dimension
	Run(ctx context.Context, client *AWSClient) ([]Finding, error)
}
