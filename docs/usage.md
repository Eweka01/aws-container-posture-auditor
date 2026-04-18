# CLI Reference

## `acpa scan`

Run a posture scan against your AWS account.

```
acpa scan [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--region` | env / config | AWS region to scan |
| `--profile` | default | AWS named profile |
| `--engine` | (all) | `ops` or `supplychain` |
| `--output` | (all) | `terminal`, `json`, `csv`, `html` |
| `--output-dir` | `./posture-report` | Directory for output files |

### Examples

```bash
# Full scan, current region
acpa scan

# Specific region and profile
acpa scan --region eu-west-1 --profile staging

# Supply chain checks only
acpa scan --engine supplychain

# HTML output only
acpa scan --output html --output-dir /tmp/audit-2026-04

# Use a role via environment variables
AWS_PROFILE=prod-readonly acpa scan --region us-east-1
```

---

## `acpa checks list`

Print a table of all available checks with IDs, dimensions, and names.

```bash
acpa checks list
```

---

## `acpa checks info <check-id>`

Show details of a specific check.

```bash
acpa checks info ops.ecs.no_autoscaling
```

---

## `acpa iam-policy`

Print the minimal read-only IAM policy required by `acpa` as JSON. Redirect to a file and create the policy via the AWS CLI:

```bash
acpa iam-policy > /tmp/acpa-policy.json
aws iam create-policy \
  --policy-name ACPAReadOnly \
  --policy-document file:///tmp/acpa-policy.json
```

---

## `acpa version`

Print the tool version.

```bash
acpa version
```

---

## Credential chain

`acpa` delegates entirely to the AWS SDK credential provider chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credentials file (`~/.aws/credentials`)
3. Shared config file (`~/.aws/config`)
4. IAM role for EC2 / ECS / EKS (instance metadata)
5. AWS SSO

Use `--profile` to select a named profile. Use `AWS_DEFAULT_REGION` or `--region` to override the region.
