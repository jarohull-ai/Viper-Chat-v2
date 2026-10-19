# Viper Chat specification changelog

## Phase 1 closure — 2026-10-19

- Recorded the Phase 1 Definition of Done and completion evidence in `MIGRATION_PLAN.md`.
- Deferred `viper-server`, the production SEED provider process and first-run credential
  provisioning to Phase 2. This is a delivery-plan sequencing decision; the frozen product scope
  is unchanged.

## Phase 1 implementation note — 2026-10-19

- Added `viper.tool_guard.v1` metadata and position-bound rule IDs to the legacy policy YAML so the
  Rust loader can reject unsupported or incomplete policy artifacts. This records implementation
  metadata; it does not change the frozen product scope or capabilities.

## 2.0.0 — 2026-10-18

- Froze the Phase 0 Native Rust product baseline as `VIPER-SPEC-2.0`.
- Defined the product invariant, required subsystems, security behavior, workbench scope and
  explicit exclusions.
- Established ADR-based change control. No post-freeze scope change is included in this entry.

## 2.1.0 — 2026-10-19 (Phase 3 addendum)

- Added the semantic SEED input/trust requirements: provenance-tagged context,
  provider-computed geometry/LID, and no approval from missing or untrusted
  evidence.
- Kept IPC v2 unchanged; semantic request fields require a separately specified
  and signed IPC v3.
- Set Phase 3 scope to semantic SEED first, followed by sandboxed execution,
  complete tool APIs, and privileged real-provider end-to-end verification.
- Normative details: [`SPECIFICATION_ADDENDUM_2.1.md`](SPECIFICATION_ADDENDUM_2.1.md)
  and [ADR-0008](adr/0008-semantic-seed-inputs-and-trust.md).
