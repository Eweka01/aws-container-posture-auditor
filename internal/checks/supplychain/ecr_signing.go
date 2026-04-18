package supplychain

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/Eweka01/aws-container-posture-auditor/internal/engine"
)

type ecrUnsignedImages struct{}

func (e *ecrUnsignedImages) ID() string { return "sc.ecr.unsigned_images" }
func (e *ecrUnsignedImages) Name() string {
	return "ECR repository contains images without Cosign signatures"
}
func (e *ecrUnsignedImages) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (e *ecrUnsignedImages) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	repos, err := listECRRepos(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, repo := range repos {
		repoName := *repo.RepositoryName
		repoURI := *repo.RepositoryUri

		// List images
		images, err := listECRImages(ctx, client, repoName)
		if err != nil || len(images) == 0 {
			continue
		}

		// Look for OCI referrers that represent Cosign signatures (tag: sha256-<digest>.sig)
		hasSig := false
		for _, img := range images {
			for _, tag := range img.ImageTags {
				if len(tag) > 4 && tag[len(tag)-4:] == ".sig" {
					hasSig = true
					break
				}
			}
			if hasSig {
				break
			}
		}

		if !hasSig {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityHigh,
				Resource:    *repo.RepositoryArn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("ECR repository %q contains no Cosign signature tags (*.sig). Images cannot be verified as built by a trusted pipeline.", repoName),
				Remediation: "Sign images at build time using Cosign with a KMS key or Sigstore:\n\n  cosign sign --key awskms:///alias/my-signing-key \\\n    " + repoURI + ":$(git rev-parse HEAD)",
				References: []string{
					"https://docs.sigstore.dev/cosign/overview/",
					"https://slsa.dev/",
				},
			})
		}
	}
	return findings, nil
}

type ecrNoSBOM struct{}

func (e *ecrNoSBOM) ID() string                  { return "sc.ecr.no_sbom" }
func (e *ecrNoSBOM) Name() string                { return "ECR images missing attached SBOM (OCI referrer)" }
func (e *ecrNoSBOM) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (e *ecrNoSBOM) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	repos, err := listECRRepos(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, repo := range repos {
		repoName := *repo.RepositoryName
		repoURI := *repo.RepositoryUri

		images, err := listECRImages(ctx, client, repoName)
		if err != nil || len(images) == 0 {
			continue
		}

		// Look for SBOM referrer tags (e.g. sha256-<digest>.sbom)
		hasSBOM := false
		for _, img := range images {
			for _, tag := range img.ImageTags {
				if len(tag) > 5 && tag[len(tag)-5:] == ".sbom" {
					hasSBOM = true
					break
				}
			}
			if hasSBOM {
				break
			}
		}

		if !hasSBOM {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityMedium,
				Resource:    *repo.RepositoryArn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("ECR repository %q has no SBOM (Software Bill of Materials) attached as an OCI referrer. Component visibility and CVE tracking depend on SBOMs.", repoName),
				Remediation: "Attach an SBOM using Syft and Cosign at build time:\n\n  syft " + repoURI + ":$(git rev-parse HEAD) -o spdx-json > sbom.spdx.json\n  cosign attach sbom --sbom sbom.spdx.json " + repoURI + ":$(git rev-parse HEAD)",
				References: []string{
					"https://github.com/anchore/syft",
					"https://docs.sigstore.dev/cosign/working_with_blobs/",
				},
			})
		}
	}
	return findings, nil
}

type ecrScanDisabled struct{}

func (e *ecrScanDisabled) ID() string                  { return "sc.ecr.scan_disabled" }
func (e *ecrScanDisabled) Name() string                { return "ECR repository has image scanning disabled" }
func (e *ecrScanDisabled) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (e *ecrScanDisabled) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	repos, err := listECRRepos(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, repo := range repos {
		if repo.ImageScanningConfiguration == nil || !repo.ImageScanningConfiguration.ScanOnPush {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityHigh,
				Resource:    *repo.RepositoryArn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("ECR repository %q does not have scan-on-push enabled. Vulnerabilities in pushed images are not automatically detected.", *repo.RepositoryName),
				Remediation: "Enable scan-on-push:\n\n  aws ecr put-image-scanning-configuration \\\n    --repository-name <name> \\\n    --image-scanning-configuration scanOnPush=true",
				References:  []string{"https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"},
			})
		}
	}
	return findings, nil
}

type ecrNoLifecyclePolicy struct{}

func (e *ecrNoLifecyclePolicy) ID() string { return "sc.ecr.no_lifecycle_policy" }
func (e *ecrNoLifecyclePolicy) Name() string {
	return "ECR repository has no lifecycle policy (image sprawl)"
}
func (e *ecrNoLifecyclePolicy) Dimension() engine.Dimension { return engine.DimensionSupplyChain }

func (e *ecrNoLifecyclePolicy) Run(ctx context.Context, client *engine.AWSClient) ([]engine.Finding, error) {
	repos, err := listECRRepos(ctx, client)
	if err != nil {
		return nil, err
	}
	var findings []engine.Finding
	for _, repo := range repos {
		repoName := *repo.RepositoryName
		_, err := client.ECR().GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{RepositoryName: &repoName})
		if err != nil {
			findings = append(findings, engine.Finding{
				CheckID:     e.ID(),
				Dimension:   e.Dimension(),
				Severity:    engine.SeverityLow,
				Resource:    *repo.RepositoryArn,
				Region:      client.Region,
				Title:       e.Name(),
				Description: fmt.Sprintf("ECR repository %q has no lifecycle policy. Unused images accumulate, increasing storage costs and the attack surface of stale images.", repoName),
				Remediation: "Add a lifecycle policy to expire old images:\n\n  aws ecr put-lifecycle-policy \\\n    --repository-name <name> \\\n    --lifecycle-policy-text '{\"rules\":[{\"rulePriority\":1,\"description\":\"Expire old images\",\"selection\":{\"tagStatus\":\"untagged\",\"countType\":\"sinceImagePushed\",\"countUnit\":\"days\",\"countNumber\":30},\"action\":{\"type\":\"expire\"}}]}'",
				References:  []string{"https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html"},
			})
		}
	}
	return findings, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func listECRRepos(ctx context.Context, client *engine.AWSClient) ([]ecrtypes.Repository, error) {
	var repos []ecrtypes.Repository
	paginator := ecr.NewDescribeRepositoriesPaginator(client.ECR(), &ecr.DescribeRepositoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		repos = append(repos, page.Repositories...)
	}
	return repos, nil
}

func listECRImages(ctx context.Context, client *engine.AWSClient, repoName string) ([]ecrtypes.ImageDetail, error) {
	var images []ecrtypes.ImageDetail
	paginator := ecr.NewDescribeImagesPaginator(client.ECR(), &ecr.DescribeImagesInput{RepositoryName: &repoName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		images = append(images, page.ImageDetails...)
	}
	return images, nil
}

// ECRSigningChecks returns all ECR supply chain check instances.
func ECRSigningChecks() []engine.Check {
	return []engine.Check{
		&ecrUnsignedImages{},
		&ecrNoSBOM{},
		&ecrScanDisabled{},
		&ecrNoLifecyclePolicy{},
	}
}
