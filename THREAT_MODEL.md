# Viper Chat v2 threat model — Phase 1

This document describes the current decision-core slice, not the complete
product. The product specification and architecture in `docs/v2/` remain
authoritative; update this model when trust boundaries or capabilities change.

## Assets

- Host files, credentials, and user data (must remain outside agent authority).
- Decision proposals, Tool Guard policy, SEED IPC keys, and verdict integrity.
- Durable trajectory events, their redacted details, and SHA-256 chain head.
- Availability and correctness of the decision path.

## Trust boundaries and assumptions

1. Human/operator to Viper process: user intent is authenticated by the host
   environment; the process must not infer extra authority.
2. Viper process to SEED provider over Unix socket: peer UID, HMAC challenge,
   framed protocol, identifiers, deadlines, and verdict schema are validated.
3. Policy/configuration to decision engine: policy files are untrusted input;
   invalid or unsupported policy prevents readiness.
4. Decision engine to SQLite ledger: writes are transactional, redacted before
   persistence, and hash-linked; database corruption must fail verification.
5. Viper process to host capabilities: Phase 1 has no executor, shell, PTY,
   network, browser, or process-spawn capability.

## Adversaries and principal threats

- Malicious or compromised local process attempts socket impersonation,
  cross-UID access, handshake replay, frame confusion, or credential theft.
- Malformed policy/protocol input attempts parser ambiguity, unknown verdict
  acceptance, or fail-open behavior.
- A caller attempts to turn a VETO, timeout, missing provider, or incomplete
  decision into approval.
- A local attacker or crash alters, truncates, reorders, or replays trajectory
  events, or causes secrets to enter persisted details.
- Resource exhaustion targets IPC deadlines, SQLite contention, or bounded
  queues.

## Controls and residual risks

- Deny by default: missing provider, invalid authentication, unsupported
  messages, and timeouts fail closed.
- Unix peer credentials plus HMAC/replay checks bind IPC to the expected peer
  and session; bounded frames and deadlines limit protocol resource use.
- Strict versioned Tool Guard parsing and first-hit precedence constrain
  proposals before SEED decisions.
- SQLite transactions, redaction, and chain verification detect incomplete or
  tampered ledger state; they do not protect against a fully privileged host
  attacker who can replace both data and software.
- No tool execution is present in this phase. Future execution, sandbox, and
  network capabilities require separate threat analysis and phase gates.

## Security priorities

Confidentiality of credentials and host files; integrity of verdicts and
trajectory; availability with bounded failure; and auditability without
persisting raw secrets. See `docs/v2/MIGRATION_PLAN.md` for test and release
gates.
