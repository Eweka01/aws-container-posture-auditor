# Check Catalog

All checks included in `acpa` v0.1.0.

---

## Operational Reliability Engine

### ECS / Fargate

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `ops.ecs.no_autoscaling` | ECS service has no auto-scaling policy | High | No Application Auto Scaling policy is attached. Service cannot scale out under load. |
| `ops.ecs.no_health_check` | ECS task definition missing container health check | High | No `healthCheck` block in the container definition. ECS cannot determine if the container is healthy. |
| `ops.ecs.latest_image_tag` | ECS task definition uses `:latest` image tag | Medium | Image reference resolves via mutable `:latest` tag. Two task launches may get different images. |
| `ops.ecs.no_logging` | ECS task definition has no log driver configured | High | No `logConfiguration` defined. Container stdout/stderr is lost. |
| `ops.ecs.missing_circuit_breaker` | ECS service deployment lacks circuit breaker | Medium | `DeploymentCircuitBreaker.enable` is false. Failed deployments will not automatically roll back. |
| `ops.ecs.single_task_count` | ECS service has desired count = 1 (no HA) | Medium | A single task provides no high availability. Any task failure causes downtime. |

### EKS

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `ops.eks.outdated_version` | EKS cluster running unsupported Kubernetes version | Critical | Cluster is on an EOL K8s version that no longer receives AWS security patches. |
| `ops.eks.no_managed_addons` | EKS cluster missing core managed add-ons | High | CoreDNS, kube-proxy, or VPC CNI are self-managed. They do not receive automatic updates. |
| `ops.eks.public_endpoint` | EKS API endpoint publicly accessible without IP restriction | High | Public endpoint is open to 0.0.0.0/0. Anyone on the internet can attempt to authenticate. |
| `ops.eks.no_logging` | EKS control plane logging disabled | Medium | No control plane log types enabled. API, audit, and authenticator logs are not collected. |
| `ops.eks.node_group_single_az` | EKS node group in single AZ | High | All nodes in one AZ. An AZ outage takes down the entire node group. |

### Lambda

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `ops.lambda.no_dlq` | Lambda function has no dead-letter queue | Medium | Failed async invocations are silently discarded. No visibility into errors. |
| `ops.lambda.deprecated_runtime` | Lambda function using deprecated runtime | Critical | Runtime is EOL and receives no security patches from AWS. |
| `ops.lambda.no_tracing` | Lambda function has X-Ray tracing disabled | Low | Distributed traces and performance insights are unavailable. |
| `ops.lambda.no_reserved_concurrency` | Critical Lambda function has no reserved concurrency | Medium | Noisy-neighbor functions can exhaust the regional concurrency limit and throttle this function. |

### Observability

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `ops.obs.no_log_retention` | CloudWatch log group has no retention policy (infinite) | Medium | Logs accumulate indefinitely, increasing costs and complicating incident response. |
| `ops.obs.no_alarms_on_critical` | Critical resource has no CloudWatch alarms | High | Capacity issues will go undetected until tasks crash. |
| `ops.obs.container_insights_off` | Container Insights disabled on ECS/EKS cluster | Medium | Task-level CPU, memory, and network metrics are not being collected. |

---

## Supply Chain Trust Engine

### ECR Signing & SBOMs

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `sc.ecr.unsigned_images` | ECR repository contains images without Cosign signatures | High | No `.sig` OCI referrer tags found. Images cannot be verified as built by a trusted pipeline. |
| `sc.ecr.no_sbom` | ECR images missing attached SBOM (OCI referrer) | Medium | No `.sbom` OCI referrer tags found. Component visibility and CVE tracking are unavailable. |
| `sc.ecr.scan_disabled` | ECR repository has image scanning disabled | High | `scanOnPush` is disabled. Vulnerabilities in pushed images are not automatically detected. |
| `sc.ecr.no_lifecycle_policy` | ECR repository has no lifecycle policy (image sprawl) | Low | Unused images accumulate, increasing storage costs and the attack surface of stale images. |

### Image Tag & Digest Policy

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `sc.img.mutable_tags` | ECR repository has IMMUTABLE tag policy disabled | High | Tags can be overwritten. An attacker with push access can silently replace a trusted image. |
| `sc.img.deployment_uses_tag_not_digest` | Deployment pulls image by tag instead of pinned digest | Medium | Tag references are mutable. Images may change between deployments. |
| `sc.img.latest_in_production` | Workload uses `:latest` tag in production | High | `:latest` is unpredictable in production. Two task launches may run different code. |

### EKS Admission Controls

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `sc.eks.no_admission_controller` | EKS cluster has no admission controller enforcing signed images | High | No Kyverno or OPA/Gatekeeper detected. Unsigned images can be deployed freely. |
| `sc.eks.no_signature_verification` | Admission controller present but no signature verification policy | High | Controller is present but no image signing policy has been detected. |

### Lambda Code Signing

| Check ID | Title | Severity | Description |
|---|---|---|---|
| `sc.lambda.no_code_signing` | Lambda function has no AWS Signer code signing configuration | Medium | Arbitrary ZIP packages can be deployed without cryptographic verification. |
| `sc.lambda.signing_not_enforced` | Lambda code signing present but not enforced (warn-only) | Medium | Signing config is in Warn mode. Unsigned packages can still be deployed. |
