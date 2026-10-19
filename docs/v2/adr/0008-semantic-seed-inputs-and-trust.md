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
