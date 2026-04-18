package ops

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

type obsNoLogRetention struct{}

func (o *obsNoLogRetention) ID() string { return "ops.obs.no_log_retention" }
func (o *obsNoLogRetention) Name() string {
	return "CloudWatch log group has no retention policy (infinite)"
}
func (o *obsNoLogRetention) Dimension() engine.Dimension { return engine.DimensionOps }

func (o *obsNoLogRetention) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	var findings []engine.Finding
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client.CloudWatchLogs(), &cloudwatchlogs.DescribeLogGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, err
		}
		for _, lg := range page.LogGroups {
			if lg.RetentionInDays == nil {
				name := ""
				if lg.LogGroupName != nil {
					name = *lg.LogGroupName
				}
				findings = append(findings, engine.Finding{
					CheckID:     o.ID(),
					Dimension:   o.Dimension(),
					Severity:    engine.SeverityMedium,
					Resource:    safeStr(lg.LogGroupArn),
					Region:      client.Region,
					Title:       o.Name(),
					Description: fmt.Sprintf("CloudWatch log group %q has no retention policy. Logs accumulate indefinitely, increasing storage costs and complicating incident response.", name),
					Remediation: "Set a retention policy appropriate to your compliance requirements:\n\n  aws logs put-retention-policy \\\n    --log-group-name <name> --retention-in-days 90",
					References:  []string{"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html"},
				})
			}
		}
	}
	return findings, nil
}

type obsNoAlarms struct{}

func (o *obsNoAlarms) ID() string                  { return "ops.obs.no_alarms_on_critical" }
func (o *obsNoAlarms) Name() string                { return "Critical resource has no CloudWatch alarms" }
func (o *obsNoAlarms) Dimension() engine.Dimension { return engine.DimensionOps }

func (o *obsNoAlarms) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	var findings []engine.Finding

	// Check ECS services for missing alarms
	clusters, _ := listECSClusters(ctx, client)
	for _, cluster := range clusters {
		services, _ := listECSServices(ctx, client, cluster)
		for _, svc := range services {
			name := *svc.ServiceName
			alarmsOut, err := client.CloudWatch().DescribeAlarmsForMetric(ctx, &cloudwatch.DescribeAlarmsForMetricInput{
				MetricName: aws.String("CPUUtilization"),
				Namespace:  aws.String("AWS/ECS"),
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("ServiceName"), Value: &name},
					{Name: aws.String("ClusterName"), Value: aws.String(lastSegment(cluster))},
				},
			})
			if err != nil || alarmsOut == nil || len(alarmsOut.MetricAlarms) == 0 {
				findings = append(findings, engine.Finding{
					CheckID:     o.ID(),
					Dimension:   o.Dimension(),
					Severity:    engine.SeverityHigh,
					Resource:    *svc.ServiceArn,
					Region:      client.Region,
					Title:       o.Name(),
					Description: fmt.Sprintf("ECS service %q has no CloudWatch alarms on CPUUtilization. Capacity issues will go undetected until tasks crash.", name),
					Remediation: "Create a CloudWatch alarm for ECS CPU utilization:\n\n  aws cloudwatch put-metric-alarm \\\n    --alarm-name ecs-<service>-cpu-high \\\n    --metric-name CPUUtilization --namespace AWS/ECS \\\n    --dimensions Name=ServiceName,Value=<service> Name=ClusterName,Value=<cluster> \\\n    --threshold 80 --comparison-operator GreaterThanThreshold \\\n    --evaluation-periods 2 --period 300 --statistic Average \\\n    --alarm-actions arn:aws:sns:...",
					References:  []string{"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/US_AlarmAtThresholdECS.html"},
				})
			}
		}
	}

	return findings, nil
}

type obsContainerInsightsOff struct{}

func (o *obsContainerInsightsOff) ID() string { return "ops.obs.container_insights_off" }
func (o *obsContainerInsightsOff) Name() string {
	return "Container Insights disabled on ECS/EKS cluster"
}
func (o *obsContainerInsightsOff) Dimension() engine.Dimension { return engine.DimensionOps }

func (o *obsContainerInsightsOff) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	var findings []engine.Finding

	// ECS clusters
	clusterARNs, _ := listECSClusters(ctx, client)
	for i := 0; i < len(clusterARNs); i += 100 {
		end := i + 100
		if end > len(clusterARNs) {
			end = len(clusterARNs)
		}
		out, err := client.ECS().DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: clusterARNs[i:end],
			Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldSettings},
		})
		if err != nil {
			continue
		}
		for _, c := range out.Clusters {
			enabled := false
			for _, s := range c.Settings {
				if s.Name == ecstypes.ClusterSettingNameContainerInsights && s.Value != nil && *s.Value == "enabled" {
					enabled = true
				}
			}
			if !enabled {
				findings = append(findings, engine.Finding{
					CheckID:     o.ID(),
					Dimension:   o.Dimension(),
					Severity:    engine.SeverityMedium,
					Resource:    *c.ClusterArn,
					Region:      client.Region,
					Title:       o.Name(),
					Description: fmt.Sprintf("ECS cluster %q has Container Insights disabled. Task-level CPU, memory, and network metrics are not being collected.", *c.ClusterName),
					Remediation: "Enable Container Insights on the cluster:\n\n  aws ecs update-cluster-settings \\\n    --cluster <cluster> \\\n    --settings name=containerInsights,value=enabled",
					References:  []string{"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html"},
				})
			}
		}
	}

	// EKS: check if amazon-cloudwatch-observability addon is installed
	eksNames, _ := listEKSClusters(ctx, client)
	for _, name := range eksNames {
		eksName := name
		addonsOut, err := client.EKS().ListAddons(ctx, &eks.ListAddonsInput{ClusterName: &eksName})
		if err != nil {
			continue
		}
		found := false
		for _, a := range addonsOut.Addons {
			if a == "amazon-cloudwatch-observability" {
				found = true
				break
			}
		}
		if !found {
			clusterOut, err := client.EKS().DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &eksName})
			arn := eksName
			if err == nil && clusterOut.Cluster != nil && clusterOut.Cluster.Arn != nil {
				arn = *clusterOut.Cluster.Arn
			}
			findings = append(findings, engine.Finding{
				CheckID:     o.ID(),
				Dimension:   o.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    arn,
				Region:      client.Region,
				Title:       o.Name(),
				Description: fmt.Sprintf("EKS cluster %q does not have the amazon-cloudwatch-observability addon. Container Insights metrics and logs are not being collected.", eksName),
				Remediation: "Install the CloudWatch Observability addon:\n\n  aws eks create-addon --cluster-name <cluster> \\\n    --addon-name amazon-cloudwatch-observability",
				References:  []string{"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-addon.html"},
			})
		}
	}

	return findings, nil
}

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ObservabilityChecks returns all observability check instances.
func ObservabilityChecks() []engine.Check {
	return []engine.Check{
		&obsNoLogRetention{},
		&obsNoAlarms{},
		&obsContainerInsightsOff{},
	}
}
