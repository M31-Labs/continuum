# Observe-Mode Production Pilot

This quickstart is for production-style observation, not enforcement. Continuum
will evaluate policy and record governed decisions, but it will not block kernel
activity unless a reviewed enforcement backend is configured for that action.

## 1. Prepare State

Keep Continuum state in a private directory controlled by the operator:

```sh
install -d -m 700 /var/lib/continuum
install -d -m 700 /var/log/continuum
```

For a developer-workstation pilot, a repository-local `.continuum/` directory is
acceptable if the repository is trusted and not writable by the agent under
test.

## 2. Configure

Create `continuum.toml`:

```toml
[project]
name = "agent-workdir"
version = "0.1.0"

[policy]
bundle = "policies/main.arb"

[audit]
kind = "jsonl"
path = "/var/log/continuum/audit.jsonl"

[subject]
default_kind = "agent"
default_mode = "ask"

[capabilities]
horizon_manifest_dir = "/etc/continuum/capabilities"

[state]
policy_store = "/var/lib/continuum/policies.json"
grant_store = "/var/lib/continuum/grants.json"
delivery_store = "/var/lib/continuum/deliveries.json"
session_store = "/var/lib/continuum/sessions.json"
airlock_store = "/var/lib/continuum/airlock.json"

[daemon]
cors_origins = ""

[grant]
max_ttl = "1h"

[enforcement]
network = "observe"
file = "observe"
process = "observe"

[approval]
kind = "cli"
```

## 3. Publish Policy

```sh
continuum policy check policies/main.arb
continuum policy publish --config continuum.toml policies/main.arb
continuum policy activate --config continuum.toml agent-workdir
continuum doctor --config continuum.toml
```

## 4. Start The Daemon

Prefer Unix socket mode for local pilots:

```sh
continuum agent start \
  --config continuum.toml \
  --unix-socket /var/run/continuum/daemon.sock \
  --auth-reads
```

For HTTP, keep the listener local and set a token:

```sh
export CONTINUUM_DAEMON_TOKEN="$(openssl rand -hex 32)"
continuum agent start --config continuum.toml --listen 127.0.0.1:8787 --auth-token "$CONTINUUM_DAEMON_TOKEN" --auth-reads
```

Check readiness:

```sh
curl -H "Authorization: Bearer $CONTINUUM_DAEMON_TOKEN" http://127.0.0.1:8787/readyz
```

## 5. Ingest Events

```sh
continuum ingest \
  --config continuum.toml \
  --daemon http://127.0.0.1:8787 \
  --daemon-token "$CONTINUUM_DAEMON_TOKEN" \
  --events events.jsonl
```

## 6. Review

```sh
continuum status --config continuum.toml
continuum audit list --path /var/log/continuum/audit.jsonl
continuum audit verify --path /var/log/continuum/audit.jsonl
continuum grant list --config continuum.toml --all
continuum airlock status --config continuum.toml
```

Before expanding scope:

- verify every denial is explainable
- review audit logs for sensitive data
- keep all grants short-lived and reasoned
- confirm operators understand observe-mode boundaries
- do not enable destructive or privileged capabilities without review
