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
continuum policy check examples/agent-workdir/policies/main.arb
continuum policy activate agent-workdir
continuum policy list
continuum policy show agent-workdir
continuum run --agent claude --repo . -- claude code
continuum ingest --events testdata/events/file_secret_access.json --approval deny
continuum sessions list
continuum sessions show agent-session-42
continuum agent start --config continuum.toml --listen 8787 --auth-token "$CONTINUUM_DAEMON_TOKEN"
curl -X POST --data-binary @events.jsonl http://127.0.0.1:8787/ingest
continuum ingest --daemon http://127.0.0.1:8787 --daemon-token "$CONTINUUM_DAEMON_TOKEN" --events events.jsonl
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
examples/demo-v0.sh
```

## V0 Surface

V0 is observe-first. It can:

- load config relative to `continuum.toml`
- consume Horizon v0 capability manifests
- register Continuum and Horizon-declared capabilities
- resolve active policies from the policy store
- compile and evaluate `.arb` policies with Arbiter
- inspect published policies with `policy list` and `policy show`
- create governed sessions for `continuum run`
- track root and child process lifecycle records for sessions when process
  events include session identity
- ingest Continuum event JSON, JSON arrays, JSONL, audit JSONL, or Horizon event envelopes
- feed local synthetic fixtures through the same source loop used by runtime sources
- normalize events into facts
- evaluate the starter agent and airlock policies
- route outcomes through registered capabilities
- ask/auto-approve/auto-deny `AskHuman` outcomes and persist scoped approval grants
- write and query audit JSONL
- create, list, revoke, prune, and evaluate temporary network/file/process grants
- persist airlock and session state
- accumulate event history into airlock behavior summaries
- serve daemon health, capabilities, sessions, grants, airlocks, audit state,
  and governed event ingestion over HTTP

V0 does not claim kernel enforcement. `observe` records decisions; `noop` is for tests and dry runs.

## Config

`continuum.toml` controls both policy inputs and local state paths. Relative
paths resolve from the config file directory.

```toml
[project]
name = "agent-workdir"
version = "0.1.0"

[policy]
bundle = "policies/main.arb"

[audit]
kind = "jsonl"
path = ".continuum/audit.jsonl"

[state]
policy_store = ".continuum/policies.json"
grant_store = ".continuum/grants.json"
delivery_store = ".continuum/deliveries.json"
session_store = ".continuum/sessions.json"
airlock_store = ".continuum/airlock.json"
```

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
  "fields": {"pid": 1234, "comm": "go", "argv_text": "go test ./...", "cwd": "/repo"}
}
```

Pass the manifest directory so Continuum can map `capability` to the emitted
event type:

```sh
continuum ingest --manifest-dir .continuum/capabilities --events horizon-events.jsonl --sessions .continuum/sessions.json
```

The local daemon exposes the same path as `POST /ingest` once started with
`--listen`. The endpoint accepts Continuum event JSON, JSON arrays, JSONL,
audit JSONL, or Horizon envelopes and returns the audit decisions written for
the batch.

Daemon HTTP listens on localhost when given a bare port such as `--listen 8787`.
Set `--auth-token` or `CONTINUUM_DAEMON_TOKEN` to require bearer-token
authentication for mutating endpoints such as `/ingest`; pass `--auth-reads`
to require the same token for read endpoints.

## Status

Pre-alpha.
