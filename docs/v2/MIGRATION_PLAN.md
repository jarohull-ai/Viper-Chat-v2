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

## Phase 2 — decision API and provider bootstrap

- Start with the `viper-server` API slice: strict decision submission, durable COMMIT receipts,
  read-only decision/trajectory inspection and chain verification. Keep it loopback-only and expose
  no execution endpoint; publish the wire contract in `protocols/VIPER_SERVER_V1.md`.
- Provide a `viper-server` executable with a bounded CLI for DB path, loopback port, SEED IPC paths,
  expected provider UID, public trust bundle, and policy selection. Document current bootstrap
  limitations in `DEPLOYMENT.md`.
- `viper-seed-provider` now serves SEED IPC v2 as a separate process, loads the Ed25519 key from
  an inherited descriptor, checks peer UID, and independently re-evaluates Tool Guard evidence.
  Its current deterministic policy-backed gate is not an independent semantic decider; no tool
  execution exists. The first-run `viper-seed-keygen` provisioner writes a
  provider-owned private credential and root-owned public keyring without
  overwriting existing paths. A hardened systemd starting template uses
  `LoadCredential` and descriptor handoff; validate it on the target host and
  confirm socket ownership/client access. Automated key rotation is deferred
  beyond this alpha checkpoint. The real-provider process test is Phase 3
  acceptance evidence; it needs root and distinct service UIDs, so run it in an
  isolated local setup or on a dedicated privileged runner.
- The server API must reject unknown request fields, enforce the 64 KiB body limit, use stable
  machine-readable errors, and expose no tool-execution capability in this phase.

Exit: loopback decision API, durable decision ledger, signed IPC v2 provider, key provisioner,
systemd starting template, and required CI cross-UID checks exist. The reference point is tag
`v2.0.0-alpha.2`. The real-provider process test is carried as Phase 3 acceptance evidence.

## Phase 3 — semantic SEED, sandbox and complete tool API

- Start with `SPECIFICATION_ADDENDUM_2.1.md` and ADR-0008: define trusted task-context provenance,
  semantic intent/context evaluation, provider-computed LID evidence, and IPC v3 without changing
  the strict IPC v2 contract. Build this native in `viper-seed`; do not reuse `seed-core` 0.1.6.
- Implement the opt-in, local-only Candle embedding backend first; then freeze a multilingual model
  bundle and versioned reference corpus by digest. Calibrate a versioned evaluator against published
  decision vectors before mapping LID/context evidence to escalation or veto. No LID threshold may
  approve a tool action by itself.
- Keep the provider explicitly policy-backed until semantic inputs, decision vectors, IPC v3
  binding and failure behavior pass their acceptance tests.
- Add `viper-sandbox`, Bubblewrap environment construction, process groups, timeouts, output limits,
  cancellation, and PTY lifecycle (`portable-pty` if the verified slice needs PTY support).
- Add approval capabilities and revalidation immediately before spawn. Accept only a non-cloneable
  `ExecutionPermit` at the spawn boundary; atomically persist its unique claim with
  `tool_execution` so ownership safety survives concurrency, crashes and restarts.
- Expand `viper-server` to the complete bounded tool API. Keep network access physically absent
  from `terminal_run`; implement `network_run` with destination and DNS-rebinding defenses,
  redirect revalidation, explicit confirmation, and the 20/hour quota. Add guarded communications
  only with their own trust lifecycle and approval boundary.
- Run a root-isolated HTTP → real provider → SQLite test with distinct UIDs and provisioned keys;
  also shadow-run equivalent v1.12 decisions before switching execution ownership.

Exit: semantic decision vectors and IPC v3 conformance pass; adversarial sandbox and executor
tests pass on the supported Linux baseline; privileged real-provider end-to-end test passes; offline
behavior cannot acquire a network namespace.

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
