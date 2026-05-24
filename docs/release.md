# Release Process

Continuum does not claim enforcement-grade production readiness until reviewed
enforcement backends exist. Releases before that point are observe-mode pilot
releases.

## Versioning

Use semantic versions with a pre-1.0 compatibility posture:

- patch: bug fixes, docs, narrow hardening
- minor: new CLI surfaces, new state schema, new capability intake behavior
- major: reserved for post-1.0 breaking changes

## Checklist

Before tagging:

- CI is green on `main`
- `go test ./...` passes locally
- `go vet ./...` passes locally
- `staticcheck ./...` passes locally
- `govulncheck ./...` passes locally with the release Go toolchain
- `go test -race ./...` passes locally
- `go test -coverprofile=coverage.out ./...` passes locally
- `examples/demo-v0.sh` passes locally
- `PRODUCTION_HARDENING.md` accurately reflects remaining gaps
- `README.md` and `SECURITY.md` match the release claims
- audit schema docs were reviewed for any audit serialization changes

## Tagging

```sh
VERSION=v0.1.0
git tag -a "$VERSION" -m "$VERSION"
git push origin "$VERSION"
```

Build metadata should be injected with ldflags:

```sh
go build \
  -ldflags "-X main.version=$VERSION -X main.commit=$(git rev-parse HEAD) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./cmd/continuum
```

## Signed Audit Schema Artifact

Every tagged release publishes an audit schema documentation artifact and signs
the checksum with Sigstore keyless signing from GitHub Actions OIDC:

- `audit-schema-docs-$VERSION.tar.gz`
- `audit-schema-docs-$VERSION.sha256`
- `audit-schema-docs-$VERSION.sha256.sigstore.json`

Build the artifact locally with:

```sh
make audit-schema-artifact VERSION="$VERSION"
```

The release workflow verifies the checksum signature identity against
`.github/workflows/release.yml` at the pushed tag before publishing the assets.

## Changelog

Maintain `CHANGELOG.md` with these sections when relevant:

- Added
- Changed
- Fixed
- Security
- Known Gaps

Every release must include an explicit observe-mode or enforcement-mode status.
