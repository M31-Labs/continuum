# Continuum

A governed capability fabric for machines.

Continuum routes machine facts and machine powers through Arbiter. It consumes
Horizon capability manifests, observes runtime behavior, evaluates governed
policies, and applies narrow typed actions.

## Thesis

Agents and automation should not receive ambient machine authority.
They should receive scoped, revocable, audited capabilities.

## Pipeline

machine event -> fact -> Arbiter -> outcome -> capability -> audit

## Modes

- Agent Workdir Guard
- CI Runner Guard
- Node Runtime Fabric
- Airlock containment

## First target

Protect a developer machine while an AI coding agent works in a repository.

```sh
continuum run --agent claude --repo . -- claude code
```

## CLI contract

```sh
continuum policy publish examples/agent-workdir/policies/main.arb
continuum policy activate agent-workdir
continuum policy list
continuum policy show agent-workdir
continuum run --agent claude --repo . -- claude code
continuum ingest --events testdata/events/file_secret_access.json --approval deny
continuum sessions list
continuum sessions show agent-session-42
continuum agent start --config continuum.toml --listen 127.0.0.1:8787
continuum capabilities
continuum grant --session agent-session-42 --capability network.connect --host github.com --port 443 --ttl 20m --reason "fetch dependency"
continuum grant --session agent-session-42 --capability file.write --path .github/workflows/test.yml --op write --ttl 20m --reason "approve CI edit"
continuum audit list
continuum audit show evt_123
continuum explain evt_123
continuum replay --baseline-policy current.arb --policy candidate.arb --events audit.jsonl
continuum airlock status
continuum airlock enter --pid 1234 --reason "wormlike fanout"
continuum airlock accumulate --events audit.jsonl
continuum airlock release --session airlock-123
```

## V0 Surface

V0 is observe-first. It can:

- load config relative to `continuum.toml`
- consume Horizon v0 capability manifests
- register Continuum and Horizon-declared capabilities
- resolve active policies from the policy store
- inspect published policies with `policy list` and `policy show`
- create governed sessions for `continuum run`
- ingest Continuum event JSON, JSON arrays, JSONL, audit JSONL, or Horizon event envelopes
- normalize events into facts
- evaluate the starter agent and airlock policies
- route outcomes through registered capabilities
- ask/auto-approve/auto-deny `AskHuman` outcomes and persist scoped approval grants
- write and query audit JSONL
- create, list, revoke, prune, and evaluate temporary network/file/process grants
- persist airlock and session state
- accumulate event history into airlock behavior summaries
- serve daemon health, capabilities, sessions, grants, airlocks, and audit state over HTTP

V0 does not claim kernel enforcement. `observe` records decisions; `noop` is for tests and dry runs.

## Doctrine

No policy gets raw kernel power.
No agent gets ambient machine power.
No worker gets broad root authority.

Policies emit typed outcomes. Continuum routes outcomes to registered
capabilities. Capabilities are narrow, declared, audited, scoped, and
revocable.

## Boundary

Horizon owns probe generation, BPF artifacts, bindings, and event transport.
Continuum owns governed ingestion, subject context, fact normalization, policy
evaluation, outcome routing, audit, grants, and containment state.

Continuum consumes Horizon `cap.json` manifests as declarations of available
machine capabilities. It does not implement Horizon probes or pretend to own
their kernel/runtime mechanics.

### Horizon Integration

Horizon emits capability manifests with schema
`m31labs.dev/horizon/capability/v0`:

```sh
hzn capabilities -o .continuum/capabilities/exec.cap.json examples/execwatch/exec.hzn
continuum capabilities --manifest-dir .continuum/capabilities
```

Continuum adapts each Horizon capability declaration into a registered
Continuum capability while preserving program, section, emitted event type, and
map access metadata. Horizon remains responsible for producing and running the
probe artifacts.

For event handoff, Continuum accepts a Horizon envelope:

```json
{
  "id": "hzn_1",
  "capability": "kernel.process.exec.observe",
  "subject": {"kind": "agent", "session": "agent-42", "agent_name": "claude", "repo_root": "/repo"},
  "fields": {"comm": "go", "argv_text": "go test ./...", "cwd": "/repo"}
}
```

Pass the manifest directory so Continuum can map `capability` to the emitted
event type:

```sh
continuum ingest --manifest-dir .continuum/capabilities --events horizon-events.jsonl
```

## Status

Pre-alpha.
