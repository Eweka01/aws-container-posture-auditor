package supplychain

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

// admissionControllerAddons are well-known addon names that provide admission control.
var admissionControllerAddons = []string{
	"kyverno",
	"opa",
	"gatekeeper",
	"aws-guard-duty-agent",
}

type eksNoAdmissionController struct{}

func (e *eksNoAdmissionController) ID() string { return "sc.eks.no_admission_controller" }
func (e *eksNoAdmissionController) Name() string {
	return "EKS cluster has no admission controller enforcing signed images"
}
func (e *eksNoAdmissionController) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (e *eksNoAdmissionController) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listEKSClustersInSC(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, name := range clusters {
		clusterName := name
		out, err := client.EKS().DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &clusterName})
		if err != nil || out.Cluster == nil {
			continue
		}
		addonsOut, err := client.EKS().ListAddons(ctx, &eks.ListAddonsInput{ClusterName: &clusterName})
		if err != nil {
			addonsOut = &eks.ListAddonsOutput{}
		}

		hasController := false
		for _, a := range addonsOut.Addons {
			aLower := strings.ToLower(a)
			for _, known := range admissionControllerAddons {
				if strings.Contains(aLower, known) {
					hasController = true
					break
				}
			}
		}

		if !hasController {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityHigh,
				Resource:    *out.Cluster.Arn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("EKS cluster %q has no known admission controller (Kyverno, OPA/Gatekeeper) installed as a managed addon. Without one, unsigned or unverified images can be deployed freely.", name),
				Remediation: "Install Kyverno as an EKS addon and deploy an image signature verification policy:\n\n  helm repo add kyverno https://kyverno.github.io/kyverno/\n  helm install kyverno kyverno/kyverno -n kyverno --create-namespace\n\nThen create a ClusterPolicy to verify Cosign signatures on all images.",
				References: []string{
					"https://kyverno.io/docs/writing-policies/verify-images/",
					"https://slsa.dev/",
				},
			})
		}
	}
	return findings, nil
}

type eksNoSignatureVerification struct{}

func (e *eksNoSignatureVerification) ID() string { return "sc.eks.no_signature_verification" }
func (e *eksNoSignatureVerification) Name() string {
	return "Admission controller present but no signature verification policy"
}
func (e *eksNoSignatureVerification) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (e *eksNoSignatureVerification) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	clusters, err := listEKSClustersInSC(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, name := range clusters {
		clusterName := name
		out, err := client.EKS().DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &clusterName})
		if err != nil || out.Cluster == nil {
			continue
		}
		addonsOut, err := client.EKS().ListAddons(ctx, &eks.ListAddonsInput{ClusterName: &clusterName})
		if err != nil || addonsOut == nil {
			continue
		}

		hasController := false
		for _, a := range addonsOut.Addons {
			aLower := strings.ToLower(a)
			for _, known := range admissionControllerAddons {
				if strings.Contains(aLower, known) {
					hasController = true
					break
				}
			}
		}

		// If no controller, the other check fires — skip here
		if !hasController {
			continue
		}

		// We cannot easily read K8s custom resources via the AWS API,
		// so we flag clusters that have a controller but no image signing addon
		hasSigningAddon := false
		for _, a := range addonsOut.Addons {
			if strings.Contains(strings.ToLower(a), "signing") || strings.Contains(strings.ToLower(a), "cosign") || strings.Contains(strings.ToLower(a), "notation") {
				hasSigningAddon = true
				break
			}
		}

		if !hasSigningAddon {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityHigh,
				Resource:    *out.Cluster.Arn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("EKS cluster %q has an admission controller installed but no image signature verification policy has been detected. The controller may not be enforcing supply chain controls.", name),
				Remediation: "Create a Kyverno ClusterPolicy to verify Cosign signatures on all images:\n\n  kubectl apply -f - <<EOF\n  apiVersion: kyverno.io/v1\n  kind: ClusterPolicy\n  metadata:\n    name: verify-image-signatures\n  spec:\n    validationFailureAction: Enforce\n    rules:\n    - name: verify-signature\n      match:\n        resources:\n          kinds: [Pod]\n      verifyImages:\n      - imageReferences: [\"*\"]\n        attestors:\n        - entries:\n          - keyless:\n              issuer: \"https://token.actions.githubusercontent.com\"\n  EOF",
				References: []string{
					"https://kyverno.io/docs/writing-policies/verify-images/sigstore/",
				},
			})
		}
	}
	return findings, nil
}

func listEKSClustersInSC(ctx context.Context, client *engine.AWSClient) ([]string, error) {
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

// EKSAdmissionChecks returns all EKS admission control check instances.
func EKSAdmissionChecks() []engine.Check {
	return []engine.Check{
		&eksNoAdmissionController{},
		&eksNoSignatureVerification{},
	}
}
