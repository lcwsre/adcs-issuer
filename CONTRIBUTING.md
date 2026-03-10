# Contributing to ADCS Issuer

We welcome contributions! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/adcs-issuer.git
   cd adcs-issuer
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

## Development

### Prerequisites

- Go 1.26+
- Docker
- kubectl + access to a Kubernetes cluster
- cert-manager v1.14+ installed in the cluster

### Build

```bash
# Build binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-w -s' -trimpath -o manager main.go

# Build Docker image
docker build --target production -t lcwsre/adcs-issuer:dev .
```

### Test

```bash
# Run all tests
go test ./... -race

# Run with coverage
go test ./... -coverprofile=coverage.out -race
go tool cover -html=coverage.out
```

### Lint

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run
```

## Submitting Changes

1. Ensure tests pass: `go test ./...`
2. Ensure code is formatted: `go fmt ./...`
3. Ensure vet passes: `go vet ./...`
4. Commit with a clear message following [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add support for new auth mode
   fix: handle redirect with preserved headers
   docs: update installation instructions
   chore: update dependencies
   ```
5. Push to your fork and open a Pull Request

## Pull Request Guidelines

- PRs should target the `main` branch
- Include a clear description of the change and why it's needed
- Add tests for new functionality
- Update documentation (README, values.yaml comments) if applicable
- One feature/fix per PR

## Code Style

- Follow standard Go conventions and [Effective Go](https://go.dev/doc/effective_go)
- Use `go fmt` and `go vet`
- Keep functions focused and small
- Add comments for exported types and functions

## Reporting Issues

- Use [GitHub Issues](https://github.com/lcwsre/adcs-issuer/issues)
- Include: Go version, Kubernetes version, cert-manager version, ADCS server version
- Provide controller logs and relevant YAML manifests (redact credentials!)

## License

By contributing, you agree that your contributions will be licensed under the BSD-3-Clause License.
