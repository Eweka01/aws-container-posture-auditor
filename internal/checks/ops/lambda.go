package ops

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

// deprecatedRuntimes lists Lambda runtimes that are EOL or deprecated.
var deprecatedRuntimes = map[lambdatypes.Runtime]bool{
	lambdatypes.RuntimeNodejs:        true,
	lambdatypes.RuntimeNodejs43:      true,
	lambdatypes.RuntimeNodejs43edge:  true,
	lambdatypes.RuntimeNodejs610:     true,
	lambdatypes.RuntimeNodejs810:     true,
	lambdatypes.RuntimeNodejs10x:     true,
	lambdatypes.RuntimeNodejs12x:     true,
	lambdatypes.RuntimeNodejs14x:     true,
	lambdatypes.RuntimeNodejs16x:     true,
	lambdatypes.RuntimePython27:      true,
	lambdatypes.RuntimePython36:      true,
	lambdatypes.RuntimePython37:      true,
	lambdatypes.RuntimePython38:      true,
	lambdatypes.RuntimeDotnetcore10:  true,
	lambdatypes.RuntimeDotnetcore20:  true,
	lambdatypes.RuntimeDotnetcore21:  true,
	lambdatypes.RuntimeDotnetcore31:  true,
	lambdatypes.RuntimeRuby25:        true,
	lambdatypes.RuntimeJava8:         true,
	lambdatypes.RuntimeGo1x:          true,
}

type lambdaNoDLQ struct{}

func (l *lambdaNoDLQ) ID() string               { return "ops.lambda.no_dlq" }
func (l *lambdaNoDLQ) Name() string             { return "Lambda function has no dead-letter queue" }
func (l *lambdaNoDLQ) Dimension() engine.Dimension { return engine.DimensionOps }

func (l *lambdaNoDLQ) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	fns, err := listLambdaFunctions(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, fn := range fns {
		if fn.DeadLetterConfig == nil || fn.DeadLetterConfig.TargetArn == nil || *fn.DeadLetterConfig.TargetArn == "" {
			findings = append(findings, engine.Finding{
				CheckID:     l.ID(),
				Dimension:   l.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    *fn.FunctionArn,
				Region:      client.Region,
				Title:       l.Name(),
				Description: fmt.Sprintf("Lambda function %q has no dead-letter queue (DLQ) configured. Failed async invocations are silently discarded.", *fn.FunctionName),
				Remediation: "Configure an SQS queue or SNS topic as the DLQ:\n\n  aws lambda update-function-configuration \\\n    --function-name <name> \\\n    --dead-letter-config TargetArn=arn:aws:sqs:us-east-1:123456789:my-dlq",
				References:  []string{"https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-dlq"},
			})
		}
	}
	return findings, nil
}

type lambdaDeprecatedRuntime struct{}

func (l *lambdaDeprecatedRuntime) ID() string               { return "ops.lambda.deprecated_runtime" }
func (l *lambdaDeprecatedRuntime) Name() string             { return "Lambda function using deprecated runtime" }
func (l *lambdaDeprecatedRuntime) Dimension() engine.Dimension { return engine.DimensionOps }

func (l *lambdaDeprecatedRuntime) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	fns, err := listLambdaFunctions(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, fn := range fns {
		if deprecatedRuntimes[fn.Runtime] {
			findings = append(findings, engine.Finding{
				CheckID:     l.ID(),
				Dimension:   l.Dimension(),
				Severity:    engine.SeverityCritical,
				Resource:    *fn.FunctionArn,
				Region:      client.Region,
				Title:       l.Name(),
				Description: fmt.Sprintf("Lambda function %q uses runtime %q which is deprecated and no longer receives security patches from AWS.", *fn.FunctionName, fn.Runtime),
				Remediation: "Update the function to a supported runtime. For Node.js 16 → 20:\n\n  aws lambda update-function-configuration \\\n    --function-name <name> --runtime nodejs20.x\n\nTest thoroughly — runtime upgrades may require code changes.",
				References: []string{
					"https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
					"https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html",
				},
			})
		}
	}
	return findings, nil
}

type lambdaNoTracing struct{}

func (l *lambdaNoTracing) ID() string               { return "ops.lambda.no_tracing" }
func (l *lambdaNoTracing) Name() string             { return "Lambda function has X-Ray tracing disabled" }
func (l *lambdaNoTracing) Dimension() engine.Dimension { return engine.DimensionOps }

func (l *lambdaNoTracing) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	fns, err := listLambdaFunctions(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, fn := range fns {
		if fn.TracingConfig == nil || fn.TracingConfig.Mode != lambdatypes.TracingModeActive {
			findings = append(findings, engine.Finding{
				CheckID:     l.ID(),
				Dimension:   l.Dimension(),
				Severity:    engine.SeverityLow,
				Resource:    *fn.FunctionArn,
				Region:      client.Region,
				Title:       l.Name(),
				Description: fmt.Sprintf("Lambda function %q does not have AWS X-Ray active tracing enabled. Distributed traces and performance insights are unavailable.", *fn.FunctionName),
				Remediation: "Enable active tracing:\n\n  aws lambda update-function-configuration \\\n    --function-name <name> --tracing-config Mode=Active",
				References:  []string{"https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html"},
			})
		}
	}
	return findings, nil
}

type lambdaNoReservedConcurrency struct{}

func (l *lambdaNoReservedConcurrency) ID() string               { return "ops.lambda.no_reserved_concurrency" }
func (l *lambdaNoReservedConcurrency) Name() string             { return "Critical Lambda function has no reserved concurrency" }
func (l *lambdaNoReservedConcurrency) Dimension() engine.Dimension { return engine.DimensionOps }

func (l *lambdaNoReservedConcurrency) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	fns, err := listLambdaFunctions(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, fn := range fns {
		name := *fn.FunctionName
		cc, err := client.Lambda().GetFunctionConcurrency(ctx, &lambda.GetFunctionConcurrencyInput{FunctionName: &name})
		if err != nil {
			continue
		}
		if cc.ReservedConcurrentExecutions == nil {
			findings = append(findings, engine.Finding{
				CheckID:     l.ID(),
				Dimension:   l.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    *fn.FunctionArn,
				Region:      client.Region,
				Title:       l.Name(),
				Description: fmt.Sprintf("Lambda function %q has no reserved concurrency. Noisy-neighbor functions can exhaust the regional concurrency limit and throttle this function.", name),
				Remediation: "Set reserved concurrency to guarantee capacity:\n\n  aws lambda put-function-concurrency \\\n    --function-name <name> --reserved-concurrent-executions 100",
				References:  []string{"https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html"},
			})
		}
	}
	return findings, nil
}

type lambdaOversizedMemory struct{}

func (l *lambdaOversizedMemory) ID() string               { return "ops.lambda.oversized_memory" }
func (l *lambdaOversizedMemory) Name() string             { return "Lambda function allocated memory significantly exceeds usage" }
func (l *lambdaOversizedMemory) Dimension() engine.Dimension { return engine.DimensionOps }

// oversizedMemoryThresholdMB flags functions allocated over this amount with no corresponding p99 usage data.
const oversizedMemoryThresholdMB = 512

func (l *lambdaOversizedMemory) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	fns, err := listLambdaFunctions(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, fn := range fns {
		if fn.MemorySize == nil || *fn.MemorySize <= oversizedMemoryThresholdMB {
			continue
		}
		allocated := *fn.MemorySize
		findings = append(findings, engine.Finding{
			CheckID:     l.ID(),
			Dimension:   l.Dimension(),
			Severity:    engine.SeverityLow,
			Resource:    *fn.FunctionArn,
			Region:      client.Region,
			Title:       l.Name(),
			Description: fmt.Sprintf("Lambda function %q is allocated %d MB. Functions over %d MB should be reviewed — over-provisioned memory inflates cost without improving performance unless the function is CPU-bound.", *fn.FunctionName, allocated, oversizedMemoryThresholdMB),
			Remediation: "Use AWS Lambda Power Tuning to find the optimal memory setting:\n\n  https://github.com/alexcasalboni/aws-lambda-power-tuning\n\nThen update:\n  aws lambda update-function-configuration \\\n    --function-name <name> --memory-size <optimal-mb>",
			References: []string{
				"https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html",
				"https://github.com/alexcasalboni/aws-lambda-power-tuning",
			},
		})
	}
	return findings, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func listLambdaFunctions(ctx context.Context, client *engine.AWSClient) ([]lambdatypes.FunctionConfiguration, error) {
	var fns []lambdatypes.FunctionConfiguration
	paginator := lambda.NewListFunctionsPaginator(client.Lambda(), &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		fns = append(fns, page.Functions...)
	}
	return fns, nil
}

// LambdaChecks returns all Lambda check instances.
func LambdaChecks() []engine.Check {
	return []engine.Check{
		&lambdaNoDLQ{},
		&lambdaDeprecatedRuntime{},
		&lambdaOversizedMemory{},
		&lambdaNoTracing{},
		&lambdaNoReservedConcurrency{},
	}
}
