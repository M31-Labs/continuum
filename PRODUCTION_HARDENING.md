# Continuum Production Hardening Checklist

This is the single production hardening checklist for the active Continuum
hardening goal. Horizon remains responsible for eBPF probe authoring, BPF C
artifacts, loading, and transport. Continuum owns the governed control plane:
daemon safety, local state, policy evaluation, grants, delivery, audit,
sessions, airlock state, and operator surfaces.

Production-ready here means safe for production-style observe-mode workloads.
It does not mean Continuum is a kernel enforcement boundary until real
enforcement backends exist and are reviewed.

## State Durability

- [x] Write JSON state files atomically with temp-file, fsync, and rename.
- [x] Tighten state file permissions to private owner-readable files.
- [x] Tighten state directory permissions to private owner-traversable dirs.
- [x] Fsync audit writes before acknowledging decisions.
- [x] Add tests for atomic JSON state writes.
- [x] Add tests for audit durability and append behavior.
- [x] Add cross-process file locking around JSON state mutation.
- [x] Add corrupt-store recovery diagnostics that preserve the bad file.
- [x] Add bounded retention/compaction for delivery, session, and audit state.
- [x] Add state schema versions and migration hooks.
- [x] Add explicit state backup/export/import commands.
- [x] Add monotonic ID generation that survives process restarts.

## Daemon Safety

- [x] Make the daemon listen on localhost by default when HTTP is enabled.
- [x] Add token authentication for mutating daemon endpoints.
- [x] Add optional token authentication for read endpoints.
- [x] Add daemon request and header size limits.
- [x] Add HTTP server read, write, idle, and shutdown timeouts.
- [x] Add graceful shutdown on SIGINT/SIGTERM.
- [x] Reject unsupported content types on ingest.
- [x] Return structured error bodies consistently.
- [x] Add per-endpoint method tests.
- [x] Add daemon readiness that validates policy, state, and registry.
- [x] Add Unix socket serving mode for local-only deployments.
- [x] Add config-driven CORS denial/allowlist, default deny.

## Policy And Capability Safety

- [x] Validate active policy existence at daemon startup.
- [x] Validate policy outcome names against registered route capabilities.
- [x] Validate policy input fields against normalized Continuum facts.
- [x] Add policy bundle provenance metadata.
- [x] Add policy activation rollback.
- [ ] Add signed capability manifest support.
- [ ] Add capability manifest digest pinning in config.
- [x] Add warning output for privileged/destructive capabilities.
- [x] Add route tests for every built-in outcome.
- [ ] Add replay gates that compare candidate policy decisions against baseline.

## Horizon Artifact Intake

- [x] Detect `.hzn` source inputs and route them through Horizon-owned export
      tooling rather than compiling them inside Continuum.
- [x] Accept Horizon exported package directories as capability sources.
- [x] Accept already compiled eBPF object references as capability artifact
      metadata without loading them directly.
- [x] Register source/sink/worker capabilities from exported Horizon package
      metadata.
- [x] Preserve BPF object path, program name, section, map names, and event
      stream names as capability metadata.
- [x] Validate artifact file existence and readability during capability load.
- [x] Record artifact digests for exported `.bpf.o`, generated bindings, and
      manifest files.
- [x] Add `continuum capabilities inspect <path>` for `.hzn`, `.cap.json`,
      exported package dirs, and compiled artifact manifests.
- [x] Add clear diagnostics when a `.hzn` file requires Horizon export first.
- [x] Document the boundary: Continuum consumes declarations and streams;
      Horizon authors, compiles, loads, and transports eBPF.
- [x] Add fixtures for `.hzn`, exported package directory, and compiled object
      reference manifests.
- [x] Add tests that artifact intake never grants raw kernel handles to policy.

## Grant And Approval Hardening

- [x] Require non-empty reasons for grants and approval overrides.
- [x] Bound maximum grant TTL in config.
- [x] Add grant renewal flow instead of silent long-lived grants.
- [x] Persist approval requester identity when available.
- [x] Record approval denials as audit events.
- [x] Add revocation delivery retry handling.
- [x] Add expired-grant pruning to daemon startup.
- [x] Add grant scope validation for network host/IP and file path forms.

## Audit Integrity

- [x] Add audit hash chaining.
- [x] Add audit chain verification command.
- [x] Add audit export with redaction controls.
- [x] Add audit query pagination.
- [x] Add audit event size limits.
- [x] Add audit clock-source metadata.
- [x] Add delivery attempt linkage checks in audit tests.
- [ ] Add signed release artifact for audit schema docs.

## Runtime And Sessions

- [x] Add session heartbeat updates.
- [x] Add stale running-session detection.
- [ ] Add process tree pruning and retention policy.
- [x] Add subject identity merge tests for session, cgroup, and repo subjects.
- [ ] Add `continuum run` environment redaction in audit/session output.
- [ ] Add child-process synthetic fixture coverage.
- [ ] Add daemon-side source lifecycle health for all registered sources.
- [ ] Add bounded source loop backpressure.

## Airlock Readiness

- [ ] Persist airlock behavior accumulators across daemon restarts.
- [ ] Add airlock release/remediation audit events.
- [x] Add airlock state transition validation tests for all legal paths.
- [ ] Add operator notes to airlock sessions.
- [ ] Add decoy capability registration without real enforcement claims.
- [ ] Add airlock retention/export commands.
- [ ] Add airlock policy replay fixtures for false-positive review.

## Operator Experience

- [x] Add `continuum doctor` for config, paths, policies, and permissions.
- [x] Add `continuum version` with commit and build metadata.
- [ ] Add structured JSON output for every inspection command.
- [x] Add clear public README status badges and safety boundary language.
- [x] Add quickstart for observe-mode production pilot.
- [x] Add systemd unit example.
- [x] Add launchd plist example.
- [ ] Add container image build.
- [ ] Add release packaging for Linux and macOS.
- [x] Add changelog and release process.

## CI And Quality Gates

- [x] Add race detector CI job.
- [x] Add `go vet` to CI.
- [x] Add staticcheck CI.
- [x] Add govulncheck CI.
- [x] Add coverage report generation.
- [ ] Add fuzz tests for event and Horizon envelope decoding.
- [ ] Add golden tests for daemon error responses.
- [ ] Add integration test for daemon ingest plus session persistence.
- [x] Add public-repo secret scanning guidance.
- [x] Add dependency update policy.

## Security Review

- [x] Document the observe-mode threat model.
- [x] Document what Continuum explicitly does not enforce yet.
- [ ] Review daemon path query parameters for local file exposure risks.
- [ ] Review audit logs for sensitive data exposure.
- [ ] Review config-relative path handling.
- [ ] Review all file permission defaults.
- [ ] Review agent environment inheritance in `continuum run`.
- [ ] Review policy and manifest trust boundaries.
- [x] Add SECURITY.md with disclosure policy.
- [ ] Perform an external security review before claiming enforcement.
