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
