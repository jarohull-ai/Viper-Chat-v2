# Viper Server HTTP API v1

This is the first Phase 2 integration surface. It accepts proposals for deterministic assessment
and exposes read-only audit data. It does not execute tools, create approvals, or grant an
`ExecutionPermit`.

## Deployment boundary

- Bind IPv4 loopback only. The crate provides `bind_loopback`; do not expose this unauthenticated
  API to a LAN, reverse proxy, or public network.
- A future remote API requires a separate authentication and threat-model review.
- JSON bodies are limited to 64 KiB. Unknown request/query fields are rejected. Errors have a stable
  `{"error":{"code":"..."}}` shape and never include database, policy, or provider internals.

## Routes

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Process liveness only; does not assert provider availability. |
| `POST /v1/decisions` | Validate, persist proposal, assess with Tool Guard + SEED, persist verdict, then return. |
| `GET /v1/decisions/{proposal_id}` | Read a persisted verdict after verifying the trajectory chain. |
| `GET /v1/trajectory/events?after_sequence=N&limit=N` | Read a verified, ordered page; limit is 1–100 (default 50). |
| `GET /v1/trajectory/verify` | Verify the full ledger and return its event count. |

## Decision submission

Request fields are exactly:

```json
{
  "id": "proposal-123",
  "trace_id": "trace-456",
  "actor": "agent-name",
  "tool": "terminal_run",
  "arguments": {"command": "cargo test"}
}
```

The server supplies the UTC RFC 3339 timestamp. IDs are limited to 128 bytes, the actor to 128
bytes, argument count to 128, and each argument value to 16 KiB. A proposal ID is one-shot: an
already-recorded proposal returns `409 PROPOSAL_ALREADY_RECORDED`.

The server awaits the `tool_proposed` database COMMIT before calling SEED. It then awaits the
`seed_verdict` COMMIT before returning `200`. The response includes the composed decision, Tool
Guard evidence, and both committed sequence/hash receipts. If SEED is unavailable, the existing
decision pipeline records and returns `VETO_DENIED`; if the durable writer fails, the API returns
`503 SERVICE_UNAVAILABLE` and never returns an approval.

## Error codes

`INVALID_REQUEST`, `PAYLOAD_TOO_LARGE`, `PROPOSAL_ALREADY_RECORDED`, `NOT_FOUND`, and
`SERVICE_UNAVAILABLE` are stable machine-readable codes. A `404` from an unknown route uses the same
JSON envelope.

## Deliberate limits

There is no production provider process or credential bootstrapper in this slice. Unit tests inject
a deterministic `SeedGate`; a server integration test also uses the real authenticated IPC client
against an in-test Unix-socket mock and verifies the durable ledger after the HTTP response. The
production Unix-socket provider and inherited-credential setup remain Phase 2 work. Event reads
currently verify the complete chain before serving data; optimize this only with an
integrity-preserving design and benchmark evidence.
