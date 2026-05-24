# Observe-Mode Threat Model

Continuum v0 is an observe-first governed control plane. It can collect events,
normalize facts, evaluate Arbiter policy, route typed outcomes, write audit
records, track grants, and record containment intent.

It does not claim to stop kernel activity unless a reviewed enforcement backend
is installed and configured for that specific action.

## Assets

- developer repositories and working trees
- local credential material
- policy bundles and capability manifests
- audit logs and local Continuum state
- temporary grants and approval decisions
- airlock sessions and behavior summaries

## Trusted Components

- Continuum daemon and CLI binaries built from reviewed commits
- local `continuum.toml` owned by the operator
- Arbiter policy compiler and evaluator
- Horizon-exported capability manifests consumed as declarations
- local filesystem permissions protecting `.continuum/` state

## Untrusted Inputs

- machine events and Horizon event envelopes
- agent commands, process arguments, file paths, and network targets
- policy and manifest files from untrusted repositories
- audit JSONL files used for replay
- daemon HTTP requests from local clients unless authenticated

## Current Controls

- daemon HTTP listens on localhost unless configured otherwise
- mutating daemon endpoints require bearer token authentication when configured
- read endpoints can require authentication
- CORS denies browser origins by default
- Unix socket mode restricts local daemon access to a private socket
- JSON state writes use private permissions, fsync, rename, and advisory locks
- corrupt JSON stores are preserved before returning diagnostics
- grants require reasons and are capped by configured maximum TTL
- capability listing warns on privileged or destructive capabilities
- Horizon artifacts are treated as declarations; Continuum does not load eBPF

## Non-Enforcement Boundaries

Observe mode does not prevent:

- a process from opening, writing, or deleting files
- a process from making network connections
- a process from spawning children
- a process from reading host credential files
- exfiltration performed before an event is observed and evaluated
- tampering by a local user who can modify Continuum state or config

Continuum records the governed decision and routes typed outcomes. Real
blocking requires a backend such as process kill, network control, Landlock,
BPF LSM, cgroup/eBPF maps, or another reviewed enforcement implementation.

## Operator Guidance

- run pilots in observe mode first
- keep `.continuum/` state outside untrusted repository writes when possible
- use short grant TTLs and require human reasons
- keep daemon HTTP on localhost or a Unix socket
- set `--auth-reads` when exposing read endpoints to shared local users
- treat policy bundles and Horizon manifests as code
- review audit logs for sensitive data before sharing them
- do not claim enforcement until backend-specific tests and review exist
