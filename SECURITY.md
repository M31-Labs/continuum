# Security Policy

Continuum is pre-alpha and currently suitable for production-style observe-mode
pilots, not as a kernel enforcement boundary.

## Reporting

Report suspected security issues privately by opening a GitHub security advisory
for `M31-Labs/continuum` or by contacting the maintainers through the M31 Labs
security channel. Do not open public issues for vulnerabilities that include
exploit details, secrets, private logs, or host-specific paths.

Include:

- affected commit or release
- deployment mode and operating system
- relevant Continuum config with secrets removed
- minimal reproduction steps
- expected and observed impact

## Supported Scope

Security reports are in scope for:

- daemon authentication, CORS, HTTP request handling, and Unix socket behavior
- policy, manifest, and audit trust boundaries
- local state permissions, corruption handling, and state mutation races
- audit log integrity and sensitive data exposure
- grant creation, revocation, expiry, and approval flows
- Horizon manifest intake as declarations consumed by Continuum

Out of scope for Continuum:

- Horizon probe authoring, eBPF C generation, loading, and event transport
- claims that observe mode blocks kernel activity
- host compromise caused by external tools run outside Continuum governance

## Public Repository Hygiene

Continuum fixtures and examples must not include real secrets, host tokens,
private keys, production audit logs, or customer data. Before publishing traces,
manifests, or audit snippets, redact:

- paths under home credential directories such as `.ssh`, `.aws`, and `.kube`
- access tokens, API keys, and bearer tokens
- repository remotes that reveal private organizations
- hostnames, IPs, process arguments, and environment values that identify
  production infrastructure

Use synthetic fixtures under `testdata/` for demos and regression tests.
