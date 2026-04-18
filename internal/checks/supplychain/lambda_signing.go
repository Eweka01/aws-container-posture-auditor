package supplychain

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

type lambdaNoCodeSigning struct{}

func (l *lambdaNoCodeSigning) ID() string                { return "sc.lambda.no_code_signing" }
func (l *lambdaNoCodeSigning) Name() string              { return "Lambda function has no AWS Signer code signing configuration" }
func (l *lambdaNoCodeSigning) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (l *lambdaNoCodeSigning) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	fns, err := listLambdaFunctionsInSC(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, fn := range fns {
		name := *fn.FunctionName
		csc, err := client.Lambda().GetFunctionCodeSigningConfig(ctx, &lambda.GetFunctionCodeSigningConfigInput{FunctionName: &name})
		if err != nil || csc == nil || csc.CodeSigningConfigArn == nil || *csc.CodeSigningConfigArn == "" {
			findings = append(findings, engine.Finding{
				CheckID:     l.ID(),
				Dimension:   l.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    *fn.FunctionArn,
				Region:      client.Region,
				Title:       l.Name(),
				Description: fmt.Sprintf("Lambda function %q has no AWS Signer code signing configuration. Arbitrary ZIP packages can be deployed without cryptographic verification.", name),
				Remediation: "Create a signing profile and attach a code signing config:\n\n  # Create a signing profile\n  aws signer put-signing-profile \\\n    --profile-name my-lambda-signing-profile \\\n    --platform-id AWSLambda-SHA384-ECDSA\n\n  # Create a code signing config\n  CSC_ARN=$(aws lambda create-code-signing-config \\\n    --description \"Enforce signed deployments\" \\\n    --allowed-publishers SigningProfileVersionArns=[<profile-version-arn>] \\\n    --code-signing-policies UntrustedArtifactOnDeployment=Enforce \\\n    --query CodeSigningConfig.CodeSigningConfigArn --output text)\n\n  # Attach to function\n  aws lambda put-function-code-signing-config \\\n    --function-name <name> \\\n    --code-signing-config-arn $CSC_ARN",
				References: []string{
					"https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html",
					"https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html",
				},
			})
		}
	}
	return findings, nil
}

type lambdaSigningNotEnforced struct{}

func (l *lambdaSigningNotEnforced) ID() string                { return "sc.lambda.signing_not_enforced" }
func (l *lambdaSigningNotEnforced) Name() string              { return "Lambda code signing present but not enforced (warn-only)" }
func (l *lambdaSigningNotEnforced) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (l *lambdaSigningNotEnforced) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	fns, err := listLambdaFunctionsInSC(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, fn := range fns {
		name := *fn.FunctionName
		csc, err := client.Lambda().GetFunctionCodeSigningConfig(ctx, &lambda.GetFunctionCodeSigningConfigInput{FunctionName: &name})
		if err != nil || csc == nil || csc.CodeSigningConfigArn == nil || *csc.CodeSigningConfigArn == "" {
			continue // no signing config — covered by the other check
		}

		// Retrieve the config to check the enforcement policy
		configOut, err := client.Lambda().GetCodeSigningConfig(ctx, &lambda.GetCodeSigningConfigInput{
			CodeSigningConfigArn: csc.CodeSigningConfigArn,
		})
		if err != nil || configOut.CodeSigningConfig == nil {
			continue
		}
		policy := configOut.CodeSigningConfig.CodeSigningPolicies
		if policy != nil && policy.UntrustedArtifactOnDeployment == "Warn" {
			findings = append(findings, engine.Finding{
				CheckID:     l.ID(),
				Dimension:   l.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    *fn.FunctionArn,
				Region:      client.Region,
				Title:       l.Name(),
				Description: fmt.Sprintf("Lambda function %q has a code signing config but it is set to Warn mode. Unsigned packages can still be deployed — the policy is advisory only.", name),
				Remediation: "Change the code signing policy to Enforce:\n\n  aws lambda update-code-signing-config \\\n    --code-signing-config-arn <csc-arn> \\\n    --code-signing-policies UntrustedArtifactOnDeployment=Enforce",
				References: []string{
					"https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-config-updates",
				},
			})
		}
	}
	return findings, nil
}

// LambdaSigningChecks returns all Lambda code signing check instances.
func LambdaSigningChecks() []engine.Check {
	return []engine.Check{
		&lambdaNoCodeSigning{},
		&lambdaSigningNotEnforced{},
	}
}
