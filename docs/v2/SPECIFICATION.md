# Viper Chat v2.0 — product specification

Specification ID: `VIPER-SPEC-2.0`
Version: `2.0.0`
Status: **FROZEN — Phase 0 baseline**
Frozen at: `2026-10-18`
Target: Native Rust, host-sovereign, fail-closed AI workbench
Migration source: Viper Chat v1.12.0

## Change control

This document is the frozen normative scope for the migration. An implementation phase may clarify
how a requirement is satisfied, but may not silently add, remove, or weaken product behavior.

- A normative change requires a written change proposal, an accepted ADR, a specification
  changelog entry, and a version bump.
- Backward-compatible scope additions increment the minor version, for example `2.1.0`; breaking
  changes increment the major version.
- Editorial corrections that do not change behavior may increment the patch version.
- Security may always be tightened immediately to contain an active vulnerability, but the change
  must be documented and versioned before the affected release is declared complete.
- Phase exit criteria may become stricter without changing this product scope. They may not be
  weakened merely to close a phase.

## Product invariant

Viper Chat v2.0 is not a chat application with optional tools. It is an auditable operating
environment for AI-assisted work. A proposed side effect may execute only after deterministic
policy evaluation, a SEED verdict, any required human approval, and durable trajectory recording.
Failure or absence of a required control means refusal.

The operating principle is: **the user authenticates, Viper navigates, and the user holds the
leash**.

## Required subsystems

- `viper-core`: domain contracts, orchestration, configuration and model routing.
- `viper-seed`: deterministic SEED boundary and first-hit-wins Tool Guard.
- `viper-sandbox`: `bwrap`, process limits, PTY and network isolation.
- `viper-db`: SQLite access and versioned migrations.
- `viper-trajectory`: redacted, tamper-evident SHA-256 event chain.
- `viper-server`: Axum HTTP API and SSE/WebSocket streams.
- `viper-ui`: lightweight workbench using CodeMirror 6 and xterm.js; no Monaco dependency.

## Normative behavior

### Decisions

Every proposed tool action receives one final result:

- `APPROVED`: policy permits the action to advance to the execution boundary.
- `VETO_DENIED`: the action is refused.
- `ESCALATE_PARLIAMENT`: execution pauses for an explicit human decision.

Tool Guard is ordered and first-hit-wins. Critical rules cannot be disabled by a UI setting.
Unknown configuration, malformed policy, unavailable SEED, missing approval, and incomplete audit
recording fail closed.

### Sandbox

- Commands run inside Bubblewrap with `--clearenv`.
- Only an explicit environment allowlist is restored (`PATH`, `HOME`, `LANG`, `TERM`).
- The workspace is the sole normal write target; system mounts are read-only.
- Credential locations including `.ssh`, `.aws`, and environment files are physically masked.
- Network is absent by default. `network_run` uses a distinct policy and requires
  `confirmNetwork: true`.
- Network actions are limited to 20 per hour and private, loopback, link-local, metadata, and raw
  socket paths are denied.

### Trajectory

The durable event vocabulary includes `plan`, `tool_proposed`, `seed_verdict`, `user_approval`,
`user_rejection`, `tool_execution`, `tool_result`, `tool_error`, `quality_gate`, `fork`,
`trust_granted`, and `trust_revoked`.

Every record contains its predecessor hash and a SHA-256 hash over a versioned canonical encoding.
Sensitive material is masked before persistence and hashing. Verification must detect removal,
reordering, modification, and broken linkage.

### Models and communication

The model layer supports Ollama, OpenAI, OpenRouter, and explicit custom model IDs. Provider model
catalogs are discovered dynamically and the configured default appears first. Untrusted e-mail is
quarantined outside LLM context. Trusted data is explicitly delimited. OTP extraction returns only
the code. Sending e-mail requires policy evaluation and human approval.

### Workbench

The UI combines chat, file explorer, CodeMirror 6 editor, xterm.js terminal, `Ctrl+P` quick open,
and a trajectory/context panel. User and agent terminal activity remain visually distinct. A
permanent SEED status is visible. “Biorę ster” pauses the agent for manual interaction. Browser
automation cannot type into password fields, including applicable shadow-DOM cases.

### Durable operations and memory

Automations use leases, renewal, bounded exponential backoff with jitter, idempotency keys, and
orphan recovery. Context compression is budget-aware, versioned, inspectable, and reversible.
Memories are project- or conversation-scoped. Lessons proposed from corrections require user
acceptance. Skills remain file-based `SKILL.md` resources.

## Explicit exclusions

- No plugin marketplace.
- No embedded VS Code or Monaco.
- No built-in LSP or debugger in the initial product.
- No hidden capabilities or implicit permission expansion.
- No big-bang replacement of v1.12.0.

## Definition of Enterprise+++

The label is earned through evidence, not naming. A subsystem is production-ready only when it has
documented trust boundaries, deterministic contracts, negative and failure-path tests, durable
recovery behavior, observability without secret leakage, upgrade/rollback instructions, and an
explicit owner. Security claims require executable tests or external evidence.
