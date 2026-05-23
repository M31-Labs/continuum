# Continuum TODO

This is the implementation backlog for taking Continuum from the current v0
scaffold to a usable governed machine fabric. Keep doctrine boundaries intact:
Horizon owns probe generation and event transport; Continuum owns governed
ingestion, fact normalization, policy evaluation, outcome routing, audit,
grants, sessions, and containment state.

## V0 Completion

- [x] Make all local state paths config-driven and config-relative.
  - policy store
  - grant store
  - session store
  - airlock store
  - audit sink
- [x] Expose daemon state endpoints using the same configured state paths.
- [ ] Add an HTTP ingest endpoint for Continuum events and Horizon envelopes.
- [x] Add `policy check` for fast policy compilation/shape validation.
- [ ] Add airlock behavior accumulation to the normal ingest path, not only the
      explicit `airlock accumulate` command.
- [ ] Persist decision delivery attempts so failed sink/worker routing is
      visible and replayable.
- [ ] Add capability manifest validation beyond required fields:
  - declared kind matches input/output shape
  - danger level is valid for backend
  - privileged/destructive capabilities require explicit owner and requirement
- [x] Add config validation for unsupported approval kinds.
- [x] Add config validation for empty state paths.
- [ ] Add golden tests for:
  - event -> fact normalization
  - outcome -> routed capability/audit event
  - Horizon manifest -> registry capability
- [ ] Add a demo script for the first target:
  - denied host credential read
  - allowed repo command
  - approval grant for CI workflow write
  - airlock fanout simulation

## V1 Foundations

- [x] Replace the local `arbiterx` starter evaluator with the real Arbiter
      compiler/VM and expert-rule session API.
- [ ] Add a Continuum-owned event source adapter for local synthetic process,
      file, and network fixtures.
- [ ] Add an actual delivery queue for source -> engine -> sink/worker flow.
- [ ] Add cgroup identity capture in `continuum run`.
- [ ] Add process-tree lifecycle tracking beyond the root process.
- [ ] Add explicit containment backend interfaces for cgroup/network namespace
      operations while keeping observe/noop as the default.
- [ ] Add revocation delivery for temporary grants, not only grant-store
      expiry.
- [ ] Add a daemon client for CLI commands so commands can use a running local
      agent instead of direct store reads when requested.

## Non-Goals Until Proven

- [ ] Do not claim kernel enforcement until a backend actually enforces.
- [ ] Do not move Horizon probe runtime responsibilities into Continuum.
- [ ] Do not give policies raw kernel handles or broad root authority.
