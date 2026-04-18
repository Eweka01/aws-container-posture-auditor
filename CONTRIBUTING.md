# Contributing

## Adding a new check (< 30 minutes)

Every check is a single Go file implementing the `engine.Check` interface:

```go
type Check interface {
    ID() string
    Name() string
    Dimension() engine.Dimension
    Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error)
}
```

### Step-by-step

**1. Create the file**

Pick the right package:
- `internal/checks/ops/` — operational reliability checks
- `internal/checks/supplychain/` — supply chain trust checks

**2. Implement the interface**

```go
package ops

import (
    "context"
    "fmt"
    "github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

type myNewCheck struct{}

func (c *myNewCheck) ID() string               { return "ops.ecs.my_new_check" }
func (c *myNewCheck) Name() string             { return "ECS service missing X" }
func (c *myNewCheck) Dimension() engine.Dimension { return engine.DimensionOps }

func (c *myNewCheck) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
    // Call the AWS SDK via client.ECS(), client.EKS(), etc.
    // Return []engine.Finding — one entry per affected resource.
    return []engine.Finding{
        {
            CheckID:     c.ID(),
            Dimension:   c.Dimension(),
            Severity:    engine.SeverityHigh,
            Resource:    "arn:aws:ecs:...",
            Region:      client.Region,
            Title:       c.Name(),
            Description: "Specific description of what was found.",
            Remediation: "Step-by-step fix with AWS CLI command.",
            References:  []string{"https://docs.aws.amazon.com/..."},
        },
    }, nil
}
```

**3. Register the check**

Add it to the `Checks()` slice at the bottom of the same file (or a nearby `*Checks()` function), then call it in `cmd/acpa/main.go` inside `registerOpsChecks()` or `registerSupplyChainChecks()`.

**4. Write a unit test**

Create `internal/checks/ops/my_new_check_test.go`. Use a mock that returns controlled AWS SDK responses. See existing `*_test.go` files for examples.

**5. Update the catalog**

Add an entry to `docs/check-catalog.md`.

### Check ID conventions

- Format: `<dimension>.<service>.<check_name>`
- Use `ops.` prefix for operational reliability checks
- Use `sc.` prefix for supply chain trust checks
- Use lowercase snake_case
- Examples: `ops.ecs.no_autoscaling`, `sc.ecr.scan_disabled`

### Severity guidelines

| Severity | When to use |
|---|---|
| Critical | EOL software, publicly exploitable misconfiguration |
| High | No HA, no logging, unsigned images in production |
| Medium | Best-practice gaps with real but indirect risk |
| Low | Cost/hygiene issues with minimal security impact |

### Remediation quality bar

Every finding **must** include a meaningful, actionable remediation message with a concrete AWS CLI command or code snippet. Generic "fix this" messages will not be accepted.

---

## Development setup

```bash
git clone https://github.com/Eweka01/aws-container-posture-auditor
cd aws-container-posture-auditor
go mod download
go test ./...
go build ./cmd/acpa
```

## Running tests

```bash
go test ./... -race -cover
```

## Code style

- `gofmt` before committing
- No comments unless the WHY is non-obvious
- Keep check files focused on one service area
