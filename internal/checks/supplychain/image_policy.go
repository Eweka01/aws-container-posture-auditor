package supplychain

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

type imgMutableTags struct{}

func (i *imgMutableTags) ID() string                  { return "sc.img.mutable_tags" }
func (i *imgMutableTags) Name() string                { return "ECR repository has IMMUTABLE tag policy disabled" }
func (i *imgMutableTags) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (i *imgMutableTags) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	repos, err := listECRRepos(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, repo := range repos {
		if repo.ImageTagMutability != "IMMUTABLE" {
			findings = append(findings, engine.Finding{
				CheckID:     i.ID(),
				Dimension:   i.Dimension(),
				Severity:    engine.SeverityHigh,
				Resource:    *repo.RepositoryArn,
				Region:      client.Region,
				Title:       i.Name(),
				Description: fmt.Sprintf("ECR repository %q allows mutable image tags. An attacker with write access can overwrite an existing tag, silently replacing a trusted image.", *repo.RepositoryName),
				Remediation: "Enable tag immutability:\n\n  aws ecr put-image-tag-mutability \\\n    --repository-name <name> \\\n    --image-tag-mutability IMMUTABLE",
				References:  []string{"https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html"},
			})
		}
	}
	return findings, nil
}

type imgDeploymentUsesTagNotDigest struct{}

func (i *imgDeploymentUsesTagNotDigest) ID() string { return "sc.img.deployment_uses_tag_not_digest" }
func (i *imgDeploymentUsesTagNotDigest) Name() string {
	return "Deployment pulls image by tag instead of pinned digest"
}
func (i *imgDeploymentUsesTagNotDigest) Dimension() engine.Dimension {
	return engine.DimensionSupplyChain
}

func (i *imgDeploymentUsesTagNotDigest) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	var findings []engine.Finding

	// ECS task definitions
	clusters, _ := listECSClustersInSC(ctx, client)
	seen := map[string]bool{}
	for _, cluster := range clusters {
		services, _ := listECSServicesInSC(ctx, client, cluster)
		for _, svc := range services {
			if svc.TaskDefinition == nil || seen[*svc.TaskDefinition] {
				continue
			}
			seen[*svc.TaskDefinition] = true
			td := *svc.TaskDefinition
			def, err := client.ECS().DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &td})
			if err != nil || def.TaskDefinition == nil {
				continue
			}
			for _, cd := range def.TaskDefinition.ContainerDefinitions {
				if cd.Image == nil {
					continue
				}
				img := *cd.Image
				if !strings.Contains(img, "@sha256:") {
					findings = append(findings, engine.Finding{
						CheckID:     i.ID(),
						Dimension:   i.Dimension(),
						Severity:    engine.SeverityMedium,
						Resource:    td,
						Region:      client.Region,
						Title:       i.Name(),
						Description: fmt.Sprintf("ECS container %q in task definition %q uses image %q referenced by tag, not digest.", *cd.Name, td, img),
						Remediation: "Pin images to immutable SHA256 digests:\n\n  image: 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp@sha256:<digest>",
						References:  []string{"https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier"},
					})
					break
				}
			}
		}
	}

	// Lambda container images
	fns, _ := listLambdaFunctionsInSC(ctx, client)
	for _, fn := range fns {
		if fn.PackageType != lambdatypes.PackageTypeImage {
			continue
		}
		fnConf, err := client.Lambda().GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: fn.FunctionName})
		if err != nil || fnConf.Code == nil || fnConf.Code.ImageUri == nil {
			continue
		}
		uri := *fnConf.Code.ImageUri
		if !strings.Contains(uri, "@sha256:") {
			findings = append(findings, engine.Finding{
				CheckID:     i.ID(),
				Dimension:   i.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    *fn.FunctionArn,
				Region:      client.Region,
				Title:       i.Name(),
				Description: fmt.Sprintf("Lambda function %q uses container image %q referenced by tag. Tag references are mutable.", *fn.FunctionName, uri),
				Remediation: "Update the Lambda function to use a digest-pinned image URI:\n\n  aws lambda update-function-code \\\n    --function-name <name> \\\n    --image-uri 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp@sha256:<digest>",
				References:  []string{"https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-images.html"},
			})
		}
	}

	return findings, nil
}

type imgLatestInProduction struct{}

func (i *imgLatestInProduction) ID() string                  { return "sc.img.latest_in_production" }
func (i *imgLatestInProduction) Name() string                { return "Workload uses :latest tag in production" }
func (i *imgLatestInProduction) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (i *imgLatestInProduction) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	var findings []engine.Finding
	clusters, _ := listECSClustersInSC(ctx, client)
	seen := map[string]bool{}
	for _, cluster := range clusters {
		services, _ := listECSServicesInSC(ctx, client, cluster)
		for _, svc := range services {
			if svc.TaskDefinition == nil || seen[*svc.TaskDefinition] {
				continue
			}
			seen[*svc.TaskDefinition] = true
			td := *svc.TaskDefinition
			def, err := client.ECS().DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &td})
			if err != nil || def.TaskDefinition == nil {
				continue
			}
			for _, cd := range def.TaskDefinition.ContainerDefinitions {
				if cd.Image == nil {
					continue
				}
				img := *cd.Image
				if strings.HasSuffix(img, ":latest") || (!strings.Contains(img, ":") && !strings.Contains(img, "@sha256:")) {
					findings = append(findings, engine.Finding{
						CheckID:     i.ID(),
						Dimension:   i.Dimension(),
						Severity:    engine.SeverityHigh,
						Resource:    td,
						Region:      client.Region,
						Title:       i.Name(),
						Description: fmt.Sprintf("ECS container %q in task definition %q uses :latest tag. In production, :latest is unpredictable — the image may change between task launches.", *cd.Name, td),
						Remediation: "Replace :latest with a specific version tag or SHA256 digest to ensure deployment reproducibility.",
						References:  []string{"https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security-tasks-containers.html"},
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── private helpers (avoid import cycle with ops package) ─────────────────────

func listECSClustersInSC(ctx context.Context, client *engine.AWSClient) ([]string, error) {
	var arns []string
	paginator := ecs.NewListClustersPaginator(client.ECS(), &ecs.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		arns = append(arns, page.ClusterArns...)
	}
	return arns, nil
}

func listECSServicesInSC(ctx context.Context, client *engine.AWSClient, clusterARN string) ([]ecstypes.Service, error) {
	var serviceARNs []string
	paginator := ecs.NewListServicesPaginator(client.ECS(), &ecs.ListServicesInput{Cluster: &clusterARN})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		serviceARNs = append(serviceARNs, page.ServiceArns...)
	}
	if len(serviceARNs) == 0 {
		return nil, nil
	}
	var services []ecstypes.Service
	for i := 0; i < len(serviceARNs); i += 10 {
		end := i + 10
		if end > len(serviceARNs) {
			end = len(serviceARNs)
		}
		out, err := client.ECS().DescribeServices(ctx, &ecs.DescribeServicesInput{
			Cluster:  &clusterARN,
			Services: serviceARNs[i:end],
		})
		if err != nil {
			continue
		}
		services = append(services, out.Services...)
	}
	return services, nil
}

func listLambdaFunctionsInSC(ctx context.Context, client *engine.AWSClient) ([]lambdatypes.FunctionConfiguration, error) {
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

// ImagePolicyChecks returns all image policy check instances.
func ImagePolicyChecks() []engine.Check {
	return []engine.Check{
		&imgMutableTags{},
		&imgDeploymentUsesTagNotDigest{},
		&imgLatestInProduction{},
	}
}
