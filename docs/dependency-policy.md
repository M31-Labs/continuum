# Dependency Update Policy

Continuum keeps its dependency surface intentionally small. Dependency updates
must preserve the governed-control-plane boundary and pass the full CI gate.

## Cadence

- review Go module updates at least monthly
- review security advisories when they are published
- update GitHub Actions major versions deliberately, not automatically
- prefer small dependency PRs over bundled upgrades

## Checks

Before merging a dependency update:

- `go test ./...`
- `go vet ./...`
- `go test -race ./...`
- `go mod tidy`
- `govulncheck ./...` once the CI gate is enabled

## Review Focus

- new transitive dependencies
- network, filesystem, or process side effects
- parser or policy-evaluation behavior changes
- audit serialization changes
- GitHub Actions permission changes

Dependency updates must not introduce ambient machine authority or widen the
capability model without an explicit design review.
