# Continuum Audit Schema

This document describes the v1 audit JSONL event shape released with
Continuum. Each line in an audit log is one JSON object matching
`docs/audit-schema.json`.

Continuum audit events record the input event, governed outcome, selected
capability route, enforcement backend label, and optional hash-chain metadata.
For v0 releases, `enforcement` is expected to be `observe` unless an operator
has explicitly configured a stub or experimental backend.

## Required fields

- `id`: stable audit event identifier.
- `time`: Continuum decision recording time in RFC3339 format.
- `subject`: normalized subject identity for the decision.
- `input_event`: normalized machine or operator event evaluated by Continuum.
- `outcome`: selected Arbiter outcome with its rule and fields.
- `decision`: normalized decision label.

## Optional integrity fields

- `clock`: clock source metadata explaining whether event time came from the
  input event or Continuum's recorded clock.
- `delivery`: delivery attempts linked to the audit event.
- `chain_prev`: previous audit chain hash, omitted for the first event.
- `chain_hash`: hash-chain digest for this audit event.

## Release artifact

Tagged releases publish a signed audit schema documentation artifact:

- `audit-schema-docs-$VERSION.tar.gz`
- `audit-schema-docs-$VERSION.sha256`
- `audit-schema-docs-$VERSION.sha256.sigstore.json`

The tarball contains this document, `audit-schema.json`, and a manifest. The
GitHub release workflow signs the checksum file with Sigstore keyless signing
using GitHub Actions OIDC. Continuum does not manage a private signing key for
this artifact.

To verify a downloaded release artifact:

```sh
sha256sum -c audit-schema-docs-v0.1.0.sha256
cosign verify-blob \
  --bundle audit-schema-docs-v0.1.0.sha256.sigstore.json \
  --certificate-identity-regexp 'https://github.com/M31-Labs/continuum/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  audit-schema-docs-v0.1.0.sha256
```

The checksum signature covers the archive digest, so consumers can pin both the
schema artifact bytes and the release workflow identity that signed them.
