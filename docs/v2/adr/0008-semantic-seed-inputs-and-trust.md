# ADR-0008: Semantic SEED inputs and trust boundary

- Status: accepted for Phase 3
- Date: 2026-10-19
- Specification: `VIPER-SPEC-2.1` addendum

## Context

The current provider independently rechecks Tool Guard evidence but is not a
semantic decider. SEED IPC v2 carries the proposal and guard result only; it
does not carry an authoritative task goal, context provenance, or geometric
evidence. Treating planner text or client-supplied LID as trusted would make
the provider sign decisions based on claims it cannot verify. Linking or
copying `seed-core` 0.1.6 is not an option: its review found correctness
defects and its license requires a separate commercial grant.

## Decision

1. Implement the semantic engine natively in `viper-seed`, with fresh code and
   documented provenance. Do not link, vendor, or copy `seed-core` 0.1.6.
2. Keep Tool Guard's hard VETO authoritative. Semantic analysis may further
   veto or escalate; it may not turn a Tool Guard veto, missing approval, or
   audit failure into approval.
3. Treat intent/context as bounded, versioned, provenance-tagged evidence.
   Planner-supplied text is untrusted and cannot stand in for human
   authorization. Context absence, staleness, or contradiction is not approval.
4. Compute LID/geometry in the provider from a provider-controlled, versioned
   evidence set. Do not accept a client-provided scalar or substitute default
   values. Missing required evidence fails closed.
5. Preserve IPC v2 unchanged. Specify IPC v3 before transporting semantic
   context; bind every added field into the request digest and provider
   signature, and reject protocol downgrade or unknown fields.
6. Keep the current provider in explicitly named policy-backed mode until the
   semantic engine, context provenance and IPC v3 conformance tests are all
   complete. Do not label it semantic before then.

## Input contract

The v3 semantic request is a strict, size-bounded envelope containing:

1. **Proposal:** the existing proposal ID, trace ID, actor, tool name,
   normalized arguments and trusted-orchestrator timestamp.
2. **Task/project context:** task ID and objective; project ID, normalized
   workspace-root identifiers and a digest/version for the project manifest or
   user-approved project summary; allowed tool families and explicit
   constraints; source kind, context version and SHA-256 digest. Free-form
   planner rationale/chain-of-thought is excluded. Because
   the current server has no authenticated human/session API, the context is
   marked `orchestrator_asserted_untrusted`; it may cause escalation or veto,
   but cannot expand capability or serve as proof of user authorization.
3. **Bounded history:** at most 16 prior normalized action summaries for the
   same task, each with outcome and trajectory event hash, plus a history
   anchor. It is treated as untrusted unless the provider can verify the anchor
   against a provider-held checkpoint; unverifiable history may not lower risk.
4. **Policy/evidence identity:** Tool Guard version and digest, plus the
   provider-loaded semantic model ID/version/digest and reference-corpus
   digest. The client never supplies a geometry score or embedding vector.

The provider validates bounds and canonicalizes the request, checks all
provider-held policy/model/corpus identities, derives the proposal/context
representations locally, then computes LID against the loaded reference corpus.
No default LID, empty-corpus approval, client-provided confidence, or fallback
to a generative model is allowed. Raw context is not copied to the ledger;
store only its digest and bounded redacted decision evidence.

## Output contract

The v3 response contains the proposal ID, final three-state verdict, stable
reason code, bounded sanitized reason, engine and policy versions, task-context
digest, and a semantic assessment with:

- context alignment: `aligned`, `uncertain`, or `mismatch`;
- provider-computed LID and the model/corpus digests used to compute it;
- history status: `verified`, `unverified`, or `not_available` and bounded
  repetition evidence;
- an assessment digest over the canonical input and deterministic assessment.

Hard Tool Guard VETO wins. Context mismatch, high calibrated LID, repeated
failed attempts, unverified risk-relevant history, or unavailable required
evidence can only escalate or veto. Low LID or an `aligned` context is never
sufficient by itself to approve an action. Thresholds are versioned policy
data calibrated against a published evaluation corpus, not magic constants.
Latency is telemetry and is excluded from the deterministic assessment digest.

## IPC v3 wire contract

IPC v3 keeps the v2 transport framing—4-byte unsigned big-endian length plus
one UTF-8 JSON document, with the same maximum frame size—but defines distinct
strict message types and the protocol identifier `viper.seed.ipc.v3`. The new
request embeds the input contract above; the signed response embeds the output
contract. The canonical request digest and Ed25519 response transcript bind
every semantic input, evidence/version digest, verdict, reason code and
assessment digest. Unknown fields, unsupported schema versions, missing
evidence and protocol mismatch fail closed.

This is a new protocol version, not an optional `context` field added to v2.
IPC v2 clients/providers remain unchanged and use only policy-backed behavior.
There is no automatic negotiation or downgrade: software selects a v2 or v3
socket/client explicitly. During migration, separate sockets may be exposed;
v3 is enabled only after its cross-version replay, signature and decision-vector
suite passes.

## Consequences

- Phase 3 starts with the domain/input contract and deterministic semantic
  evaluation, before expanding execution capabilities.
- The provider cannot infer user intent from command text alone. A trusted
  context-registration/approval path must be designed and tested as part of
  the semantic slice.
- LID claims require a reproducible corpus/version and tests for malformed,
  empty, stale, and adversarial evidence.
- Existing IPC v2 clients remain compatible, but cannot use semantic mode.
- A real-provider, distinct-UID end-to-end test remains required before the
  slice is considered complete.

## Acceptance evidence

- Independent decision vectors for intent/context mismatch, missing evidence,
  high-LID escalation, repetition, hard VETO precedence, and unavailable
  provider behavior.
- Cross-version IPC tests prove v2 remains unchanged and v3 binds all semantic
  inputs in the digest/signature.
- Provenance and versioning tests demonstrate that context/evidence cannot be
  silently substituted or downgraded.
- Root-isolated HTTP → real provider → SQLite test with provisioned credentials.
