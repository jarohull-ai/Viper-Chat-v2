# Viper Chat v2.1 specification addendum

Status: accepted scope for Phase 3, 2026-10-19  
Base: frozen `VIPER-SPEC-2.0`  
Specification ID: `VIPER-SPEC-2.1`  
Version: `2.1.0`

This addendum extends, but does not edit, the frozen v2.0 baseline. If it
conflicts with the baseline, the stricter fail-closed behavior applies until a
versioned ADR resolves the conflict.

## Semantic SEED

- `viper-seed` remains the product-owned deterministic decision engine. It
  must not depend on or copy `seed-core` 0.1.6; that component has unresolved
  correctness and commercial-license issues.
- Semantic evaluation receives a bounded, versioned task context with explicit
  provenance. Planner-supplied intent and context are untrusted evidence, not
  user authorization. Missing, malformed, stale, or contradictory context may
  only reduce a verdict to escalation or veto; it must never grant authority.
- Geometry/LID is computed inside the provider from provider-controlled,
  versioned evidence. A client-supplied LID, confidence, or verdict is never
  trusted. If evidence needed for a policy decision is unavailable, evaluation
  fails closed; no synthetic default metrics are permitted.
- Semantic evidence cannot override a Tool Guard VETO, required human approval,
  or failed audit persistence. Only the existing precedence applies:
  `VETO_DENIED > ESCALATE_PARLIAMENT > APPROVED`.
- IPC v2 remains strict and unchanged. Any request-context extension requires
  a separately specified, strictly validated IPC v3; v2 clients/providers must
  not silently accept or ignore the new fields.

## Phase 3 product slice

Phase 3 delivers the semantic decision path first, then the sandboxed terminal
and complete tool API. Tool execution remains impossible until a durable
decision and any required human approval are bound to the exact normalized
request. `terminal_run`, explicit `network_run`, and guarded communication
endpoints each retain separate capabilities and policy checks.

The real-provider HTTP → IPC → SQLite process test uses distinct service UIDs
and exercises the provisioned key path. It runs in an isolated local root
environment or a dedicated privileged runner; ordinary CI continues to run
unit tests and its dedicated cross-UID IPC checks.
