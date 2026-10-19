# Local component reuse assessment

Assessment date: 2026-10-18. Reuse requires a separate source, license, API, test and threat review.

## `seed-core` 0.1.6

Location inspected: `/home/jaro/.gemini/antigravity/scratch/seed-core`
Decision: **candidate, not approved**

Useful assets:

- Native Rust domain vocabulary for the three requested verdicts.
- Library, CLI/server and C-FFI integration surfaces.
- Initial tests for destructive operations, secrets, network and escalation.

Blocking findings:

- An unknown `profile_mode` bypasses both `OFFLINE_STRICT` and `HOST_SOVEREIGN` network branches;
  configuration is therefore fail-open.
- The repetition guard stores a reason string but compares it with the next action intent, so the
  intended repeated-failure detection does not operate as described.
- The audit chain is in-memory, uses an ad-hoc string concatenation, and does not bind every emitted
  field such as the timestamp.
- Regex coverage is illustrative rather than a complete enforcement boundary.
- The custom license requires explicit commercial permission for enterprise deployment. The
  project owner may grant that permission, but the grant must be recorded for downstream users.

The observed fail-open path is an unknown profile, not proof that a missing `seed-core` process is
currently treated as approval. Viper Chat nevertheless treats missing, unavailable, timed-out or
invalid SEED as `VETO_DENIED`; Phase 1 must prove each case independently.

Next evidence required: fix the fail-open paths, define canonical serialization, add persistence and
tamper verification, fuzz deserialization/FFI, test concurrent decisions, and document protocol
version negotiation.

### Binding decision for Viper Chat v2.0

1. **`viper-seed` replaces the integration role of `seed-core` inside Viper Chat.** It owns the
   Tool Guard, fail-closed policy composition, the stable `SeedGate` boundary, and the rule that no
   action advances without a recorded verdict.
2. **`viper-seed` is not a wrapper around `seed-core` 0.1.6.** Viper Chat must not link its library,
   load its C-FFI artifact, or spawn its binary in Phase 1. Its known fail-open and audit defects
   make it unsuitable for the trusted computing base.
3. **`seed-core` will be repaired as an independent project and release.** That work may reuse the
   findings above, but it is not on the Viper Chat critical path and Phase 1 must not wait for it.
4. **A corrected future `seed-core` may return only as an optional external SEED provider.** It must
   implement the versioned Unix-socket protocol and pass the same conformance suite as any other
   provider. `viper-seed` remains the authoritative composer and may overrule the provider; the
   provider may never bypass Tool Guard, trajectory, or human approval.
5. **Readmission requires evidence.** A new source and license review, closed fail-open findings,
   protocol conformance, fuzz and negative tests, concurrency tests, durable audit semantics, and a
   dedicated acceptance ADR are mandatory. The commercial/distribution grant must be recorded in
   the repository before the dependency is enabled in a distributable build.

This decision separates product progress from component repair: Viper Chat gets a stable boundary
now, while `seed-core` can mature without forcing a later architectural rewrite. The binding
architectural record is `docs/v2/adr/0003-viper-seed-owns-decision-boundary.md`.

## `jfp-box` 0.4.1

Location inspected: `/home/jaro/Desktop/JFP BOX`
Decision: **candidate for policy parsing, not runtime enforcement**

The library clearly states that it validates manifest consistency and does not start processes,
mount filesystems, open networks, or enforce an OS sandbox. Its ordered structures, stable error
codes and property-test dependencies are promising. A protocol compatibility review is required
before combining its manifest grammar with JFP-A2A.

## `viper-boxd` 0.1.0-alpha.2

Location inspected: `/home/jaro/Desktop/JFP BOX/viper-boxd`
Decision: **research source, not approved runtime**

The package describes itself as an unprivileged simulator. It contains useful admission, lineage,
IPC, capability and gateway work, but cannot be treated as the production sandbox. Its
PolyForm-Noncommercial license also needs an explicit distribution decision for the intended
product.

## Reuse rule

No component enters the trusted computing base by file copy. Accepted code must arrive through a
reviewable dependency or a documented import with provenance, license decision, threat analysis,
tests and an ADR. Similar naming does not imply compatibility.
