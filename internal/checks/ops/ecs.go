package ops

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aastypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

// ── ECS checks ────────────────────────────────────────────────────────────────

type ecsNoAutoscaling struct{}

func (e *ecsNoAutoscaling) ID() string                  { return "ops.ecs.no_autoscaling" }
func (e *ecsNoAutoscaling) Name() string                { return "ECS service has no auto-scaling policy" }
func (e *ecsNoAutoscaling) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *ecsNoAutoscaling) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listECSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, cluster := range clusters {
		services, err := listECSServices(ctx, client, cluster)
		if err != nil {
			continue
		}
		for _, svc := range services {
			arn := *svc.ServiceArn
			clusterName := lastSegment(cluster)
			svcName := *svc.ServiceName
			resourceID := fmt.Sprintf("service/%s/%s", clusterName, svcName)

			out, err := client.AppAutoScaling().DescribeScalableTargets(ctx, &applicationautoscaling.DescribeScalableTargetsInput{
				ServiceNamespace: aastypes.ServiceNamespaceEcs,
				ResourceIds:      []string{resourceID},
			})
			if err != nil || out == nil || len(out.ScalableTargets) == 0 {
				findings = append(findings, engine.Finding{
					CheckID:     e.ID(),
					Dimension:   e.Dimension(),
					Severity:    engine.SeverityHigh,
					Resource:    arn,
					Region:      client.Region,
					Title:       e.Name(),
					Description: fmt.Sprintf("ECS service %q has no Application Auto Scaling policy attached.", svcName),
					Remediation: "Register the service as a scalable target and attach a target tracking or step scaling policy:\n\n  aws application-autoscaling register-scalable-target \\\n    --service-namespace ecs \\\n    --resource-id service/<cluster>/<service> \\\n    --scalable-dimension ecs:service:DesiredCount \\\n    --min-capacity 1 --max-capacity 10",
					References:  []string{"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-auto-scaling.html"},
				})
			}
		}
	}
	return findings, nil
}

type ecsNoHealthCheck struct{}

func (e *ecsNoHealthCheck) ID() string                  { return "ops.ecs.no_health_check" }
func (e *ecsNoHealthCheck) Name() string                { return "ECS task definition missing container health check" }
func (e *ecsNoHealthCheck) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *ecsNoHealthCheck) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listECSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	seen := map[string]bool{}
	for _, cluster := range clusters {
		services, err := listECSServices(ctx, client, cluster)
		if err != nil {
			continue
		}
		for _, svc := range services {
			if svc.TaskDefinition == nil {
				continue
			}
			td := *svc.TaskDefinition
			if seen[td] {
				continue
			}
			seen[td] = true
			def, err := client.ECS().DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &td})
			if err != nil || def.TaskDefinition == nil {
				continue
			}
			for _, cd := range def.TaskDefinition.ContainerDefinitions {
				if cd.HealthCheck == nil {
					findings = append(findings, engine.Finding{
						CheckID:     e.ID(),
						Dimension:   e.Dimension(),
						Severity:    engine.SeverityHigh,
						Resource:    td,
						Region:      client.Region,
						Title:       e.Name(),
						Description: fmt.Sprintf("Container %q in task definition %q has no health check defined.", *cd.Name, td),
						Remediation: "Add a healthCheck block to your container definition:\n\n  \"healthCheck\": {\n    \"command\": [\"CMD-SHELL\", \"curl -f http://localhost/health || exit 1\"],\n    \"interval\": 30, \"timeout\": 5, \"retries\": 3\n  }",
						References:  []string{"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_HealthCheck.html"},
					})
					break
				}
			}
		}
	}
	return findings, nil
}

type ecsLatestImageTag struct{}

func (e *ecsLatestImageTag) ID() string                  { return "ops.ecs.latest_image_tag" }
func (e *ecsLatestImageTag) Name() string                { return "ECS task definition uses :latest image tag" }
func (e *ecsLatestImageTag) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *ecsLatestImageTag) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listECSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	seen := map[string]bool{}
	for _, cluster := range clusters {
		services, err := listECSServices(ctx, client, cluster)
		if err != nil {
			continue
		}
		for _, svc := range services {
			if svc.TaskDefinition == nil {
				continue
			}
			td := *svc.TaskDefinition
			if seen[td] {
				continue
			}
			seen[td] = true
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
						CheckID:     e.ID(),
						Dimension:   e.Dimension(),
						Severity:    engine.SeverityMedium,
						Resource:    td,
						Region:      client.Region,
						Title:       e.Name(),
						Description: fmt.Sprintf("Container %q uses image %q which resolves via mutable :latest tag.", *cd.Name, img),
						Remediation: "Pin the image to a specific digest or immutable tag:\n\n  image: 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp@sha256:<digest>",
						References:  []string{"https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier"},
					})
					break
				}
			}
		}
	}
	return findings, nil
}

type ecsNoLogging struct{}

func (e *ecsNoLogging) ID() string                  { return "ops.ecs.no_logging" }
func (e *ecsNoLogging) Name() string                { return "ECS task definition has no log driver configured" }
func (e *ecsNoLogging) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *ecsNoLogging) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listECSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	seen := map[string]bool{}
	for _, cluster := range clusters {
		services, err := listECSServices(ctx, client, cluster)
		if err != nil {
			continue
		}
		for _, svc := range services {
			if svc.TaskDefinition == nil {
				continue
			}
			td := *svc.TaskDefinition
			if seen[td] {
				continue
			}
			seen[td] = true
			def, err := client.ECS().DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &td})
			if err != nil || def.TaskDefinition == nil {
				continue
			}
			for _, cd := range def.TaskDefinition.ContainerDefinitions {
				if cd.LogConfiguration == nil {
					findings = append(findings, engine.Finding{
						CheckID:     e.ID(),
						Dimension:   e.Dimension(),
						Severity:    engine.SeverityHigh,
						Resource:    td,
						Region:      client.Region,
						Title:       e.Name(),
						Description: fmt.Sprintf("Container %q in task definition %q has no log driver configured. Container output is lost.", *cd.Name, td),
						Remediation: "Configure awslogs log driver in the container definition:\n\n  \"logConfiguration\": {\n    \"logDriver\": \"awslogs\",\n    \"options\": {\n      \"awslogs-group\": \"/ecs/my-service\",\n      \"awslogs-region\": \"us-east-1\",\n      \"awslogs-stream-prefix\": \"ecs\"\n    }\n  }",
						References:  []string{"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html"},
					})
					break
				}
			}
		}
	}
	return findings, nil
}

type ecsMissingCircuitBreaker struct{}

func (e *ecsMissingCircuitBreaker) ID() string { return "ops.ecs.missing_circuit_breaker" }
func (e *ecsMissingCircuitBreaker) Name() string {
	return "ECS service deployment lacks circuit breaker"
}
func (e *ecsMissingCircuitBreaker) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *ecsMissingCircuitBreaker) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listECSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, cluster := range clusters {
		services, err := listECSServices(ctx, client, cluster)
		if err != nil {
			continue
		}
		for _, svc := range services {
			cb := svc.DeploymentConfiguration
			if cb == nil || cb.DeploymentCircuitBreaker == nil || !cb.DeploymentCircuitBreaker.Enable {
				findings = append(findings, engine.Finding{
					CheckID:     e.ID(),
					Dimension:   e.Dimension(),
					Severity:    engine.SeverityMedium,
					Resource:    *svc.ServiceArn,
					Region:      client.Region,
					Title:       e.Name(),
					Description: fmt.Sprintf("ECS service %q does not have a deployment circuit breaker enabled. Failed deployments will not automatically roll back.", *svc.ServiceName),
					Remediation: "Enable the circuit breaker with rollback in your service configuration:\n\n  aws ecs update-service \\\n    --cluster <cluster> --service <service> \\\n    --deployment-configuration '{\"deploymentCircuitBreaker\":{\"enable\":true,\"rollback\":true}}'",
					References:  []string{"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html"},
				})
			}
		}
	}
	return findings, nil
}

type ecsSingleTaskCount struct{}

func (e *ecsSingleTaskCount) ID() string                  { return "ops.ecs.single_task_count" }
func (e *ecsSingleTaskCount) Name() string                { return "ECS service has desired count = 1 (no HA)" }
func (e *ecsSingleTaskCount) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *ecsSingleTaskCount) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listECSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, cluster := range clusters {
		services, err := listECSServices(ctx, client, cluster)
		if err != nil {
			continue
		}
		for _, svc := range services {
			if svc.DesiredCount == 1 {
				findings = append(findings, engine.Finding{
					CheckID:     e.ID(),
					Dimension:   e.Dimension(),
					Severity:    engine.SeverityMedium,
					Resource:    *svc.ServiceArn,
					Region:      client.Region,
					Title:       e.Name(),
					Description: fmt.Sprintf("ECS service %q has desiredCount=1. A single task provides no high availability; any task failure causes downtime.", *svc.ServiceName),
					Remediation: "Set desiredCount >= 2 and spread tasks across multiple AZs using placement strategies:\n\n  aws ecs update-service --cluster <cluster> --service <service> --desired-count 2",
					References:  []string{"https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/availability.html"},
				})
			}
		}
	}
	return findings, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func listECSClusters(ctx context.Context, client *engine.AWSClient) ([]string, error) {
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

func listECSServices(ctx context.Context, client *engine.AWSClient, clusterARN string) ([]ecstypes.Service, error) {
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

func lastSegment(arn string) string {
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

// ECSChecks returns all ECS check instances.
func ECSChecks() []engine.Check {
	return []engine.Check{
		&ecsNoAutoscaling{},
		&ecsNoHealthCheck{},
		&ecsLatestImageTag{},
		&ecsNoLogging{},
		&ecsMissingCircuitBreaker{},
		&ecsSingleTaskCount{},
	}
}
