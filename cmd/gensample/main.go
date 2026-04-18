package main

import (
	"context"
	"os"
	"time"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
	"github.com/Eweka01/aws-container-posture-auditor/internal/report"
)

func main() {
	results := []engine.Result{
		{Check: &stub{"ops.eks.outdated_version", engine.DimensionOps}, Findings: []engine.Finding{
			{CheckID: "ops.eks.outdated_version", Dimension: engine.DimensionOps, Severity: engine.SeverityCritical, Resource: "arn:aws:eks:us-east-1:123456789012:cluster/prod-apps", Region: "us-east-1", Title: "EKS cluster running unsupported Kubernetes version", Description: "EKS cluster \"prod-apps\" is running Kubernetes 1.24 which is no longer supported by AWS. End-of-life clusters receive no security patches.", Remediation: "Upgrade the cluster:\n  aws eks update-cluster-version --name prod-apps --kubernetes-version 1.31", References: []string{"https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html"}},
		}},
		{Check: &stub{"ops.lambda.deprecated_runtime", engine.DimensionOps}, Findings: []engine.Finding{
			{CheckID: "ops.lambda.deprecated_runtime", Dimension: engine.DimensionOps, Severity: engine.SeverityCritical, Resource: "arn:aws:lambda:us-east-1:123456789012:function:api-handler", Region: "us-east-1", Title: "Lambda function using deprecated runtime", Description: "Lambda function \"api-handler\" uses runtime nodejs16.x which is deprecated and receives no security patches.", Remediation: "Update to nodejs20.x:\n  aws lambda update-function-configuration --function-name api-handler --runtime nodejs20.x"},
		}},
		{Check: &stub{"ops.ecs.no_autoscaling", engine.DimensionOps}, Findings: []engine.Finding{
			{CheckID: "ops.ecs.no_autoscaling", Dimension: engine.DimensionOps, Severity: engine.SeverityHigh, Resource: "arn:aws:ecs:us-east-1:123456789012:service/prod/checkout", Region: "us-east-1", Title: "ECS service has no auto-scaling policy", Description: "ECS service \"checkout\" has no Application Auto Scaling policy attached.", Remediation: "aws application-autoscaling register-scalable-target --service-namespace ecs --resource-id service/prod/checkout --scalable-dimension ecs:service:DesiredCount --min-capacity 1 --max-capacity 10"},
			{CheckID: "ops.ecs.no_autoscaling", Dimension: engine.DimensionOps, Severity: engine.SeverityHigh, Resource: "arn:aws:ecs:us-east-1:123456789012:service/prod/payments", Region: "us-east-1", Title: "ECS service has no auto-scaling policy", Description: "ECS service \"payments\" has no Application Auto Scaling policy attached.", Remediation: "aws application-autoscaling register-scalable-target --service-namespace ecs ..."},
		}},
		{Check: &stub{"ops.ecs.no_health_check", engine.DimensionOps}, Findings: []engine.Finding{
			{CheckID: "ops.ecs.no_health_check", Dimension: engine.DimensionOps, Severity: engine.SeverityHigh, Resource: "arn:aws:ecs:us-east-1:123456789012:task-definition/checkout:42", Region: "us-east-1", Title: "ECS task definition missing container health check", Description: "Container \"app\" in task definition \"checkout:42\" has no health check defined.", Remediation: "Add a healthCheck block to the container definition:\n  \"healthCheck\": {\"command\": [\"CMD-SHELL\", \"curl -f http://localhost/health || exit 1\"], \"interval\": 30}"},
		}},
		{Check: &stub{"ops.obs.no_log_retention", engine.DimensionOps}, Findings: []engine.Finding{
			{CheckID: "ops.obs.no_log_retention", Dimension: engine.DimensionOps, Severity: engine.SeverityMedium, Resource: "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/checkout", Region: "us-east-1", Title: "CloudWatch log group has no retention policy", Description: "Log group \"/ecs/checkout\" has no retention policy. Logs accumulate indefinitely.", Remediation: "aws logs put-retention-policy --log-group-name /ecs/checkout --retention-in-days 90"},
			{CheckID: "ops.obs.no_log_retention", Dimension: engine.DimensionOps, Severity: engine.SeverityMedium, Resource: "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/payments", Region: "us-east-1", Title: "CloudWatch log group has no retention policy", Description: "Log group \"/ecs/payments\" has no retention policy.", Remediation: "aws logs put-retention-policy --log-group-name /ecs/payments --retention-in-days 90"},
		}},
		{Check: &stub{"sc.ecr.unsigned_images", engine.DimensionSupplyChain}, Findings: []engine.Finding{
			{CheckID: "sc.ecr.unsigned_images", Dimension: engine.DimensionSupplyChain, Severity: engine.SeverityHigh, Resource: "arn:aws:ecr:us-east-1:123456789012:repository/checkout", Region: "us-east-1", Title: "ECR repository contains images without Cosign signatures", Description: "ECR repository \"checkout\" contains no Cosign signature tags (.sig OCI referrers).", Remediation: "Sign images at build time:\n  cosign sign --key awskms:///alias/my-signing-key 123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:$(git rev-parse HEAD)", References: []string{"https://docs.sigstore.dev/cosign/overview/"}},
		}},
		{Check: &stub{"sc.img.mutable_tags", engine.DimensionSupplyChain}, Findings: []engine.Finding{
			{CheckID: "sc.img.mutable_tags", Dimension: engine.DimensionSupplyChain, Severity: engine.SeverityHigh, Resource: "arn:aws:ecr:us-east-1:123456789012:repository/api", Region: "us-east-1", Title: "ECR repository has IMMUTABLE tag policy disabled", Description: "ECR repository \"api\" allows mutable tags. Tags can be silently overwritten.", Remediation: "aws ecr put-image-tag-mutability --repository-name api --image-tag-mutability IMMUTABLE"},
		}},
		{Check: &stub{"sc.eks.no_admission_controller", engine.DimensionSupplyChain}, Findings: []engine.Finding{
			{CheckID: "sc.eks.no_admission_controller", Dimension: engine.DimensionSupplyChain, Severity: engine.SeverityHigh, Resource: "arn:aws:eks:us-east-1:123456789012:cluster/prod-apps", Region: "us-east-1", Title: "EKS cluster has no admission controller enforcing signed images", Description: "No known admission controller (Kyverno, OPA/Gatekeeper) was detected on cluster \"prod-apps\". Unsigned images can be deployed freely.", Remediation: "Install Kyverno and create a signature verification ClusterPolicy:\n  helm install kyverno kyverno/kyverno -n kyverno --create-namespace"},
		}},
		{Check: &stub{"sc.lambda.no_code_signing", engine.DimensionSupplyChain}, Findings: []engine.Finding{
			{CheckID: "sc.lambda.no_code_signing", Dimension: engine.DimensionSupplyChain, Severity: engine.SeverityMedium, Resource: "arn:aws:lambda:us-east-1:123456789012:function:api-handler", Region: "us-east-1", Title: "Lambda function has no AWS Signer code signing configuration", Description: "Lambda function \"api-handler\" has no code signing config. Arbitrary ZIP packages can be deployed.", Remediation: "Create a signing profile and attach a code signing configuration to the function."},
		}},
	}

	r := report.Build(results, "123456789012", "us-east-1", 12345*time.Millisecond)

	if err := os.MkdirAll("examples/sample-report", 0755); err != nil {
		panic(err)
	}
	f, err := os.Create("examples/sample-report/posture-report.html")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := report.RenderHTML(r, f); err != nil {
		panic(err)
	}
}

type stub struct {
	id  string
	dim engine.Dimension
}

func (s *stub) ID() string                  { return s.id }
func (s *stub) Name() string                { return s.id }
func (s *stub) Dimension() engine.Dimension { return s.dim }
func (s *stub) Run(_ context.Context, _ *engine.AWSClient) ([]engine.Finding, error) {
	return nil, nil
}
