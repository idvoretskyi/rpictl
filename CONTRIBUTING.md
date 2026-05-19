# Contributing to rpictl

Thank you for your interest in contributing. This document covers the basics.

## Developer Certificate of Origin

All commits must be signed off with the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "your commit message"
```

This adds a `Signed-off-by: Your Name <your@email.com>` trailer to every commit. Pull requests with unsigned commits will not be merged.

## Development Setup

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the full build, test, and release workflow.

Quick start:

```bash
git clone https://github.com/idvoretskyi/rpictl.git
cd rpictl
go build ./...
go test ./...
```

Requirements: Go 1.25+, `golangci-lint` (see docs/DEVELOPMENT.md for exact versions).

## Submitting a Pull Request

1. Fork the repo and create a branch from `main`.
2. Make your changes. Add or update tests as appropriate.
3. Run `go test ./...` and `golangci-lint run` — both must pass.
4. Sign off all commits (`git commit -s`).
5. Open a PR against `main`. Fill in the pull request template.

## What We're Looking For

- Bug fixes with a reproduction case
- Support for additional Raspberry Pi hardware (RPi 4/5 — see the device profiles in `internal/config/profiles.go`)
- Improved idempotency or error handling in agent steps
- Documentation improvements

## What We're NOT Looking For (Right Now)

- Multi-node cluster support — intentional non-goal for v0.x
- Non-Raspberry-Pi hardware — out of scope
- Docker support — rpictl uses k3s built-in containerd exclusively
- Ansible / cloud-init alternatives — rpictl's SSH+agent model is deliberate

If you're unsure whether a contribution fits, open an issue first to discuss.

## Reporting Bugs

Use the [bug report template](https://github.com/idvoretskyi/rpictl/issues/new?template=bug_report.yml).

## Suggesting Features

Use the [feature request template](https://github.com/idvoretskyi/rpictl/issues/new?template=feature_request.yml).

## Security Vulnerabilities

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
