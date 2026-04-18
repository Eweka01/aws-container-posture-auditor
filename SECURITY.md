# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✓ |

## Reporting a vulnerability

If you discover a security vulnerability in `acpa`, please **do not open a public GitHub issue**.

Email: **oseweka1@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You will receive an acknowledgement within 48 hours and a resolution timeline within 7 days.

## Scope

This tool is read-only and never modifies AWS infrastructure. Relevant vulnerability classes include:

- Credential leakage (logs, error messages, reports)
- Path traversal in `--output-dir`
- HTML injection in the report renderer
- Dependency vulnerabilities in `go.sum`

## Out of scope

- Findings accuracy (open a regular issue)
- AWS API rate limiting behavior
- Features or check logic
