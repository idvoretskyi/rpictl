# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | Yes |
| < 0.1.0 | No |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub private security advisories](https://github.com/idvoretskyi/rpictl/security/advisories/new) to report a vulnerability confidentially. You will receive a response within 7 days.

When reporting, please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof of concept
- The version of rpictl affected
- Any suggested fix, if you have one

## Scope

rpictl is a CLI tool that:
- Connects to Raspberry Pi hosts over SSH using credentials you provide
- Uploads and executes a pre-built agent binary on the Pi
- Fetches and rewrites kubeconfig from the Pi to your local machine

Areas of particular security interest:
- SSH credential handling and host key verification
- Agent binary integrity (no signature verification in v0.1.0)
- Kubeconfig file permissions
- Any command injection via host/username/path values

## Disclosure Process

1. You report via GitHub private security advisory
2. We confirm receipt within 7 days
3. We investigate and develop a fix
4. We release a patched version and publish a CVE if warranted
5. You are credited in the release notes (unless you prefer anonymity)
