# Continuum Security Review Notes

Date: 2026-05-24

Scope: Continuum v0 production-style observe-mode workloads. This review does
not certify kernel enforcement. Enforcement claims remain blocked until
backend-specific review is completed.

## Daemon Path Query Parameters

Reviewed read endpoints and ingest path parameters. The daemon now rejects
state, policy, audit, and airlock path query overrides by default. Embedders
must explicitly set `HTTPOptions.AllowPathQueryOverrides` for tests or tightly
controlled local tooling. `continuum ingest --daemon` no longer sends local
state paths to the daemon; it relies on the daemon's configured paths.

## Audit Sensitive Data

Raw audit logs can contain file paths, hostnames, process arguments, raw event
payloads, subject identifiers, and outcome fields. Operators must treat raw
audit JSONL as sensitive local state. Redacted sharing should use
`continuum audit export` with `--redact-fields`, `--redact-raw`, and
`--redact-subject`. Redacted exports clear audit chain fields because the
exported record no longer hashes to the original event.

## Config-Relative Paths

Relative paths in `continuum.toml` resolve relative to the config file
directory through `config.Resolve`. Absolute paths remain absolute. Digest pin
entries are resolved when the pin key is path-shaped. Operators should keep
config files outside untrusted repository write paths for production pilots.

## File Permission Defaults

State directories are created with `0700`; JSON state, locks, audit logs, and
private export files are created or repaired to `0600`. Unix daemon sockets are
created with `0600`. Standard output remains the caller's responsibility, so
operators should redirect exports to files when preserving private mode matters.

## Agent Environment Inheritance

`continuum run` preserves the existing default of inheriting the parent
environment. For production-style pilots, run with `--clean-env` and explicit
`--env KEY=VALUE` entries to avoid handing ambient tokens to the child process.
Continuum records redacted command arguments and session metadata; it does not
record the full child environment.

## Policy And Manifest Trust Boundaries

Policy bundles and Horizon manifests are executable governance inputs and must
be treated as code. Production pilots should use digest pins and require
manifest signatures for Horizon capability manifests. Continuum registers
Horizon declarations and records artifact metadata; it does not load eBPF
objects or pass raw kernel handles into policy.

## External Review Gate

No external enforcement security review has been completed for Continuum v0.
The release posture is observe-mode only. Before any claim that Continuum blocks
kernel activity or provides a host enforcement boundary, commission and record
an external review for the specific enforcement backend, policy routes, and
deployment mode.
