package ops

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

// supportedK8sVersions — versions with active AWS support as of 2026.
// Update this list as new versions are released.
var supportedK8sVersions = map[string]bool{
	"1.29": true,
	"1.30": true,
	"1.31": true,
	"1.32": true,
}

type eksOutdatedVersion struct{}

func (e *eksOutdatedVersion) ID() string { return "ops.eks.outdated_version" }
func (e *eksOutdatedVersion) Name() string {
	return "EKS cluster running unsupported Kubernetes version"
}
func (e *eksOutdatedVersion) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *eksOutdatedVersion) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listEKSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, name := range clusters {
		out, err := client.EKS().DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
		if err != nil || out.Cluster == nil {
			continue
		}
		ver := ""
		if out.Cluster.Version != nil {
			ver = *out.Cluster.Version
		}
		if !supportedK8sVersions[ver] {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityCritical,
				Resource:    *out.Cluster.Arn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("EKS cluster %q is running Kubernetes %s which is no longer supported by AWS. End-of-life clusters receive no security patches.", name, ver),
				Remediation: "Upgrade the cluster to a supported version:\n\n  aws eks update-cluster-version --name <cluster> --kubernetes-version 1.31\n\nReview the EKS upgrade guide before proceeding: https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html",
				References:  []string{"https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html"},
			})
		}
	}
	return findings, nil
}

type eksNoManagedAddons struct{}

func (e *eksNoManagedAddons) ID() string                  { return "ops.eks.no_managed_addons" }
func (e *eksNoManagedAddons) Name() string                { return "EKS cluster missing core managed add-ons" }
func (e *eksNoManagedAddons) Dimension() engine.Dimension { return engine.DimensionOps }

var coreAddons = []string{"coredns", "kube-proxy", "vpc-cni"}

func (e *eksNoManagedAddons) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listEKSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, name := range clusters {
		out, err := client.EKS().DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
		if err != nil || out.Cluster == nil {
			continue
		}
		addonsOut, err := client.EKS().ListAddons(ctx, &eks.ListAddonsInput{ClusterName: &name})
		if err != nil {
			continue
		}
		installed := map[string]bool{}
		for _, a := range addonsOut.Addons {
			installed[strings.ToLower(a)] = true
		}
		var missing []string
		for _, req := range coreAddons {
			if !installed[req] {
				missing = append(missing, req)
			}
		}
		if len(missing) > 0 {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityHigh,
				Resource:    *out.Cluster.Arn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("EKS cluster %q is missing core managed add-ons: %s. Self-managed add-ons do not receive automatic security patches.", name, strings.Join(missing, ", ")),
				Remediation: "Install missing add-ons as EKS managed add-ons:\n\n  aws eks create-addon --cluster-name <cluster> --addon-name vpc-cni\n  aws eks create-addon --cluster-name <cluster> --addon-name coredns\n  aws eks create-addon --cluster-name <cluster> --addon-name kube-proxy",
				References:  []string{"https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html"},
			})
		}
	}
	return findings, nil
}

type eksPublicEndpoint struct{}

func (e *eksPublicEndpoint) ID() string { return "ops.eks.public_endpoint" }
func (e *eksPublicEndpoint) Name() string {
	return "EKS API endpoint publicly accessible without IP restriction"
}
func (e *eksPublicEndpoint) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *eksPublicEndpoint) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listEKSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, name := range clusters {
		out, err := client.EKS().DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
		if err != nil || out.Cluster == nil || out.Cluster.ResourcesVpcConfig == nil {
			continue
		}
		vpc := out.Cluster.ResourcesVpcConfig
		if vpc.EndpointPublicAccess && (len(vpc.PublicAccessCidrs) == 0 || (len(vpc.PublicAccessCidrs) == 1 && vpc.PublicAccessCidrs[0] == "0.0.0.0/0")) {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityHigh,
				Resource:    *out.Cluster.Arn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("EKS cluster %q has a public API endpoint with no IP CIDR restrictions (0.0.0.0/0). Anyone on the internet can attempt to authenticate.", name),
				Remediation: "Restrict public access to known corporate CIDRs or disable public endpoint entirely:\n\n  aws eks update-cluster-config --name <cluster> \\\n    --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs='203.0.113.0/24'",
				References:  []string{"https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html"},
			})
		}
	}
	return findings, nil
}

type eksNoLogging struct{}

func (e *eksNoLogging) ID() string                  { return "ops.eks.no_logging" }
func (e *eksNoLogging) Name() string                { return "EKS control plane logging disabled" }
func (e *eksNoLogging) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *eksNoLogging) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listEKSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, name := range clusters {
		out, err := client.EKS().DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
		if err != nil || out.Cluster == nil {
			continue
		}
		loggingEnabled := false
		if out.Cluster.Logging != nil {
			for _, setup := range out.Cluster.Logging.ClusterLogging {
				if setup.Enabled != nil && *setup.Enabled && len(setup.Types) > 0 {
					loggingEnabled = true
					break
				}
			}
		}
		if !loggingEnabled {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    *out.Cluster.Arn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("EKS cluster %q has no control plane log types enabled. API, audit, authenticator, controller manager, and scheduler logs are not being collected.", name),
				Remediation: "Enable control plane logging:\n\n  aws eks update-cluster-config --name <cluster> \\\n    --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
				References:  []string{"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html"},
			})
		}
	}
	return findings, nil
}

type eksNodeGroupSingleAZ struct{}

func (e *eksNodeGroupSingleAZ) ID() string                  { return "ops.eks.node_group_single_az" }
func (e *eksNodeGroupSingleAZ) Name() string                { return "EKS node group in single AZ" }
func (e *eksNodeGroupSingleAZ) Dimension() engine.Dimension { return engine.DimensionOps }

func (e *eksNodeGroupSingleAZ) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listEKSClusters(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, name := range clusters {
		ng, err := client.EKS().ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: &name})
		if err != nil {
			continue
		}
		for _, ngName := range ng.Nodegroups {
			ngOut, err := client.EKS().DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   &name,
				NodegroupName: &ngName,
			})
			if err != nil || ngOut.Nodegroup == nil {
				continue
			}
			if len(ngOut.Nodegroup.Subnets) <= 1 {
				findings = append(findings, engine.Finding{
					CheckID:     e.ID(),
					Dimension:   e.Dimension(),
					Severity:    engine.SeverityHigh,
					Resource:    *ngOut.Nodegroup.NodegroupArn,
					Region:      client.Region,
					Title:       e.Name(),
					Description: fmt.Sprintf("Node group %q in EKS cluster %q spans only one AZ. An AZ outage will take down all nodes in this group.", ngName, name),
					Remediation: "Update the node group to span subnets in at least 2 AZs:\n\n  aws eks update-nodegroup-config --cluster-name <cluster> \\\n    --nodegroup-name <nodegroup> \\\n    --subnets subnet-aaa subnet-bbb subnet-ccc",
					References:  []string{"https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html"},
				})
			}
		}
	}
	return findings, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func listEKSClusters(ctx context.Context, client *engine.AWSClient) ([]string, error) {
	var names []string
	paginator := eks.NewListClustersPaginator(client.EKS(), &eks.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		names = append(names, page.Clusters...)
	}
	return names, nil
}

// EKSChecks returns all EKS check instances.
func EKSChecks() []engine.Check {
	return []engine.Check{
		&eksOutdatedVersion{},
		&eksNoManagedAddons{},
		&eksPublicEndpoint{},
		&eksNoLogging{},
		&eksNodeGroupSingleAZ{},
	}
}
