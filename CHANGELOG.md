# Changelog

All notable changes to Continuum will be documented in this file.

Continuum is currently pre-alpha and observe-mode only.

## Unreleased

### Added

- Production hardening checklist.
- Horizon artifact intake for `.hzn`, exported package directories, `.cap.json`,
  and compiled `.bpf.o` metadata references.
- Daemon readiness, token auth, CORS denial, Unix socket serving, and structured
  error responses.
- Durable JSON state writes with private permissions, fsync, advisory locks, and
  corrupt-store preservation.
- Grant reason and maximum TTL hardening.
- CI jobs for tests, `go vet`, and race detection.
- Security policy, observe-mode threat model, service manager examples, and
  release/dependency policy docs.

### Known Gaps

- No kernel enforcement boundary is claimed in observe mode.
- State migrations, audit hash chaining, and release packaging remain open.
