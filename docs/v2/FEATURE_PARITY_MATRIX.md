# Feature parity matrix

Status values: `legacy`, `slice`, `planned`, `blocked`.

| Capability | v1.12.0 evidence | Native owner | Status | Cutover gate |
|---|---|---|---|---|
| Tool Guard | `src/tool-guard.ts`, YAML, tests | `viper-seed` | slice | Full rule corpus and differential tests |
| Tool approval | `routes/tools.ts` | core/server/db | planned | Bound, expiring approval capability |
| Terminal sandbox | `src/tools.ts` | `viper-sandbox` | planned | Escape and cancellation suite |
| Network command | separate legacy path + quota | sandbox/core/db | planned | DNS/redirect revalidation and quota recovery |
| Browser takeover | pause API + UI | server/ui | planned | Agent pause is race-free and visible |
| Password refusal | browser guard | sandbox/server | planned | DOM and shadow-DOM E2E tests |
| Conversations/messages | SQLite + Fastify | db/server/core | legacy | Migrated data and streaming parity |
| Model providers | provider adapters | core/server | legacy | Provider-neutral contract tests |
| File explorer | guarded file routes | server/ui | legacy | Traversal and symlink parity |
| Memories/lessons/skills | SQLite tables and APIs | db/core | legacy | Approval and versioning semantics |
| Automations | scheduler tables/runtime | db/core | legacy | Leases, idempotency, restart recovery |
| Quality gate | offline Bubblewrap gate | sandbox/core | legacy | Structured result and immutable lineage |
| Usage accounting | `usage_log` | db/core | legacy | Streaming/cached token reconciliation |
| Trajectory hash chain | absent in v1.12 DB | trajectory/db | slice | Remaining tamper/recovery and migration fixtures |
| Trusted e-mail | target-only | core/db/server | planned | Quarantine and injection test suite |
| Integrated workbench | partial legacy UI | ui/server | planned | Chat/editor/terminal/audit E2E suite |

This matrix is updated with every slice. `legacy` never means automatically safe or accepted; it
only identifies an existing behavior that must be understood before replacement.
