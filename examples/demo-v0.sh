#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/continuum-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [[ -n "${CONTINUUM_BIN:-}" ]]; then
  continuum=("$CONTINUUM_BIN")
else
  continuum=(go run ./cmd/continuum)
fi

repo="$WORK/repo"
mkdir -p "$repo/.github/workflows"

cat > "$WORK/host-secret.json" <<JSON
{
  "id": "evt_demo_secret",
  "kind": "file.open",
  "subject": {
    "kind": "agent",
    "session": "agent-demo",
    "agent_name": "claude",
    "repo_root": "$repo"
  },
  "fields": {
    "path": "$HOME/.ssh/id_ed25519",
    "op": "read"
  }
}
JSON

cat > "$WORK/go-test.json" <<JSON
{
  "id": "evt_demo_test",
  "kind": "process.exec",
  "subject": {
    "kind": "agent",
    "session": "agent-demo",
    "agent_name": "claude",
    "repo_root": "$repo"
  },
  "fields": {
    "comm": "go",
    "argv_text": "go test ./...",
    "cwd": "$repo"
  }
}
JSON

cat > "$WORK/ci-write.json" <<JSON
{
  "id": "evt_demo_ci",
  "kind": "file.access",
  "subject": {
    "kind": "agent",
    "session": "agent-demo",
    "agent_name": "claude",
    "repo_root": "$repo"
  },
  "fields": {
    "path": "$repo/.github/workflows/test.yml",
    "op": "write"
  }
}
JSON

cd "$ROOT"

echo "== denied host credential read =="
"${continuum[@]}" ingest \
  --policy examples/agent-workdir/policies/main.arb \
  --events "$WORK/host-secret.json" \
  --audit "$WORK/audit.jsonl" \
  --no-airlock

echo
echo "== allowed repo command =="
"${continuum[@]}" ingest \
  --policy examples/agent-workdir/policies/main.arb \
  --events "$WORK/go-test.json" \
  --audit "$WORK/audit.jsonl" \
  --no-airlock

echo
echo "== approval grant for CI workflow write =="
"${continuum[@]}" ingest \
  --policy examples/agent-workdir/policies/main.arb \
  --events "$WORK/ci-write.json" \
  --audit "$WORK/audit.jsonl" \
  --grants "$WORK/grants.json" \
  --approval allow \
  --no-airlock

echo
echo "== airlock fanout simulation =="
"${continuum[@]}" airlock simulate \
  --fixture testdata/events/worm_fanout.json \
  --policy examples/airlock/policies/main.arb \
  --audit "$WORK/audit.jsonl" \
  --store "$WORK/airlock.json"

echo
echo "audit=$WORK/audit.jsonl"
