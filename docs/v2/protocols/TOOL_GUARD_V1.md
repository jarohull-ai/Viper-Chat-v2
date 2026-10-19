# Tool Guard v1 policy contract

- Schema: `viper.tool_guard.v1`
- Source: `config/tool-guard.yaml`
- Rules: 31 ordered legacy rules
- Ordering: YAML sequence order, first match wins
- Digest: lowercase SHA-256 over the exact UTF-8 source bytes

Rust loads only a regular file no larger than 1 MiB. Unknown fields, categories, actions, severity,
missing category defaults, unsupported schema versions, wrong rule counts, malformed YAML, invalid
expressions and unsupported special expressions fail startup. Rule IDs are `TG-001` through
`TG-031` and are bound to the frozen ordered positions. Changing count or order requires a new
schema version and a differential review.

`CRITICAL` is always a block, including guard level `off`. Category defaults map legacy `block` to
VETO, `warn` to escalation and `allow` to no added restriction. `strict` upgrades a `HIGH` escalation
to VETO; `off` skips noncritical rules. Network private-address and raw-socket invariants remain
separate hard blocks at every level.

Legacy JavaScript regex lookahead is not supported by Rust's regex engine. Rule `TG-024` (curl/wget
without an explicit timeout) is represented by a structured predicate over each shell segment,
which checks for a command token, an HTTP URL and absence of both timeout flags. It does not carry a
regex approximation into production.

## Compatibility evidence and known legacy overlap

The current Rust positive corpus covers each reachable legacy rule ID and checks first-hit ordering.
Legacy rule `TG-017` duplicates the broader root deletion rule `TG-016` and cannot win under the
existing first-hit-wins order; both actions are VETO. Similarly, timeout-free `curl | interpreter`
commands match `TG-024` before `TG-026/027`; supplying a timeout flag makes the code-execution rule
observable. These are properties of the existing order and are preserved pending an explicit policy
version change.

The same checked-in fixture corpus is exercised by Rust and TypeScript, including positive hits,
first-hit IDs, one exclusion, network invariants and a benign near miss. It is not yet exhaustive:
Phase 1 exit still requires exclusion fixtures for every applicable rule, network on/off variants,
and broader benign near misses across both implementations, with every intentional difference
reviewed.
