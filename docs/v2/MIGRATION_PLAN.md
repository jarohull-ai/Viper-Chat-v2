# Viper Chat v2.0 — incremental migration plan

The migration uses a strangler pattern. Viper Chat v1.12.0 stays runnable while complete vertical
slices move behind stable contracts. A phase ends only when its exit criteria pass; calendar weeks
are planning hints, not acceptance criteria.

## Phase 0 — baseline and safety contracts (complete)

- Preserve the v1.12.0 verification suite as a regression oracle.
- Record the target specification, trust boundaries, parity matrix, and reuse assessment.
- Establish a Rust workspace and the no-execution decision slice.
- Prove fail-closed SEED behavior, Tool Guard precedence, redaction, deterministic hashing, and chain
  verification.

Exit: TypeScript tests, collaboration tests, and Rust tests pass; no Rust code can execute a tool.

## Phase 1 — durable decision core (complete)

- Deliver the Rust decision engine in `viper-seed`, durable SQLite ledger in `viper-db`, and
  versioned Tool Guard policy.
- Keep the SEED Unix-socket client fail-closed and covered by protocol, authentication and failure
  tests. `seed-core` is not linked or spawned; see `COMPONENT_REUSE_ASSESSMENT.md`.
- Defer the production provider process, credential provisioner, and HTTP/API layer to Phase 2.

### Phase 1 Definition of Done

> The decision engine (`viper-seed`) with its durable ledger (`viper-db`) and versioned policy
> (Tool Guard) is 100% tested, including the cross-UID test in isolation. The code is committed.

Acceptance evidence:

- The workspace Rust suite covers the ledger, policy parsing/evaluation, SEED IPC authentication,
  fail-closed behavior and recovery paths; cross-UID `SO_PEERCRED` integration passes in an isolated,
  network-disabled Linux container (UID 65534).
- `npm run verify`, `npm run verify:collaboration`, `npm run verify:rust`, formatting, and Clippy
  pass. The durable trajectory chain verifies after reopen.
- New-repository CI in `.github/workflows/ci.yml` must run the actual cross-UID peer-credential
  test as root; an unprivileged test run that reports `ok` after skipping does not satisfy this gate.
- Phase 1 implementation and its test evidence are committed before the release tag is created.

Exit: all acceptance evidence above passes, and Phase 1 code is committed.

## Phase 2 — API and sandboxed terminal slice

- Start with the `viper-server` API slice: strict decision submission, durable COMMIT receipts,
  read-only decision/trajectory inspection and chain verification. Keep it loopback-only and expose
  no execution endpoint; publish the wire contract in `protocols/VIPER_SERVER_V1.md`.
- Add the production SEED provider process and first-run credential provisioner. Load the same
  versioned key record via a private OS credential descriptor; never fall back to `.env`.
- The server API must reject unknown request fields, enforce the 64 KiB body limit, use stable
  machine-readable errors, and expose no tool-execution capability in this phase.
- Add `viper-sandbox`, Bubblewrap environment construction, process groups, timeouts, output limits,
  cancellation, and PTY lifecycle.
- Keep networking physically absent from `terminal_run`.
- Add approval capabilities and revalidation immediately before spawn.
- Accept only a non-cloneable `ExecutionPermit` at the spawn boundary. Atomically persist a unique
  permit claim with the `tool_execution` transition so ownership safety also survives concurrent
  processes, crashes and restarts.
- Shadow-run equivalent v1.12 commands and compare decisions before switching execution ownership.

Exit: adversarial filesystem, secret, process, cancellation, and sandbox escape suites pass on the
supported Linux baseline.

## Phase 3 — network broker and model gateway

- Implement the distinct `network_run` capability, destination validation, DNS rebinding defenses,
  redirect revalidation, confirmation, and the 20/hour quota.
- Add Ollama first, then OpenAI and OpenRouter behind one provider-neutral streaming interface.
- Record token usage, provider errors, cancellation, and sanitized request lineage.

Exit: offline behavior cannot acquire a network namespace; provider contract and quota recovery
tests pass.

## Phase 4 — chat and workbench

- Move conversation/message APIs, streaming, file explorer and quick-open.
- Serve CodeMirror 6 and xterm.js from pinned local assets with a restrictive CSP.
- Add trajectory/context panels and permanent SEED status.

Exit: accessibility, reconnect, large-output, path traversal, symlink escape, CSP, and browser E2E
tests pass.

## Phase 5 — trusted communication, automation and memory

- Add quarantined e-mail ingestion, trust lifecycle, OTP-only extraction and guarded sending.
- Add leases, renewal, idempotency, orphan recovery and bounded backoff for automations.
- Add versioned context summaries, memories, approved lessons and skills.

Exit: spoofing, prompt-injection, duplicate delivery, lease contention, crash recovery and restore
tests pass.

## Phase 6 — cutover and hardening

- Complete the parity matrix and data migration rehearsal.
- Publish `SECURITY.md`, STRIDE threat model, compliance evidence map, operations/runbook, SBOM,
  provenance and release signing.
- Run fuzzing, dependency audit, load/soak tests and an external security review.
- Keep a tested rollback path through the first stable v2 releases.

Exit: no critical parity gaps, rehearsed rollback, signed release artifacts, and approved production
readiness review.
