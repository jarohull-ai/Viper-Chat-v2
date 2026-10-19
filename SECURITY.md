# Security policy

Viper Chat v2 is in active development. The current Phase 1 Rust workspace does
not execute tools and must not be treated as a production-ready security
boundary until the relevant migration-plan exit criteria are met.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, or personal
data. Use GitHub's private vulnerability reporting for this repository if it is
enabled; otherwise contact the maintainer privately through
https://github.com/jarohull-ai. Include affected commit/version, impact, and a
minimal reproduction. Allow time for coordinated remediation before public
disclosure.

## Scope

Reports concerning SEED IPC authentication, fail-closed decision behavior,
Tool Guard policy parsing/evaluation, trajectory integrity/redaction, and
credential handling are in scope. See [`THREAT_MODEL.md`](THREAT_MODEL.md) and
the v2 protocol documents under [`docs/v2/protocols`](docs/v2/protocols).
