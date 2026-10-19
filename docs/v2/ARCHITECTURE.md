# Viper Chat v2.0 — target architecture

## Shape

```text
Browser workbench
  |  HTTP + SSE/WebSocket
viper-server
  |
viper-core (use cases and domain contracts)
  |--- viper-seed -------- deterministic policy + external SEED adapter
  |--- viper-trajectory -- redaction + canonical SHA-256 chain
  |--- viper-db ---------- SQLite repositories + migrations
  |--- viper-sandbox ----- bwrap + PTY + network broker
  `--- model providers --- Ollama / OpenAI / OpenRouter / custom
```

Dependency arrows point inward toward domain contracts. Provider SDK types, Axum extractors, SQLx
rows, and process handles must not leak into `viper-core`.

## Decision path

```text
proposal
  -> validate domain shape
  -> append tool_proposed
  -> Tool Guard verdict
  -> SEED verdict (unavailable = VETO)
  -> compose with precedence VETO > ESCALATE > APPROVED
  -> append seed_verdict
  -> optional human approval
  -> append user_approval/user_rejection
  -> sandbox executor
  -> append tool_execution and tool_result/tool_error
```

The first Rust slice stops after `seed_verdict`. It intentionally has no executor API.

## Trust boundaries

1. **Browser to server:** all input is untrusted; authenticate state-changing requests and validate
   schemas and sizes.
2. **Model to orchestrator:** model output is a proposal, never authority. Tool names and arguments
   are parsed into closed domain types.
3. **Orchestrator to SEED/policy:** timeouts, malformed output, unknown profiles and unavailable
   processes fail closed.
4. **Orchestrator to sandbox/host:** only approved structured requests cross the boundary; the
   executor independently revalidates authorization freshness.
5. **Viper to external network/services:** explicit network capability, destination policy, bounded
   quotas, redacted logging, and human confirmation apply.

## Architectural rules

- There is one composition point for final decisions; routes may not recreate security policy.
- Approval is a short-lived capability tied to proposal ID, normalized arguments hash, user and
  expiry. It is not a mutable boolean.
- Trajectory writes are part of the state transition. `viper-db` returns opaque committed receipts,
  while the executor accepts only a separate, non-cloneable permit bound to the committed decision
  and approval evidence. Execution must not start if the pre-execution event or the durable unique
  permit claim cannot be committed.
- Canonical hash encoding is versioned and does not rely on JSON object insertion order.
- Secrets are encrypted where storage is necessary and otherwise represented only by references.
- Provider adapters are replaceable and never receive ambient host credentials.
- The legacy TypeScript app remains the behavior oracle until each vertical slice meets its exit
  criteria.
