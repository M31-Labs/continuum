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
- `go test -race ./...` passes locally
- `examples/demo-v0.sh` passes locally
- `PRODUCTION_HARDENING.md` accurately reflects remaining gaps
- `README.md` and `SECURITY.md` match the release claims

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

## Changelog

Maintain `CHANGELOG.md` with these sections when relevant:

- Added
- Changed
- Fixed
- Security
- Known Gaps

Every release must include an explicit observe-mode or enforcement-mode status.
