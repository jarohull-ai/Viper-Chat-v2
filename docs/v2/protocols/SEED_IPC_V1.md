# SEED IPC v1 wire contract

- Protocol: `viper.seed.ipc.v1`
- Status: Phase 1 implementation slice
- Transport: Unix stream socket
- Framing: unsigned 32-bit big-endian byte length followed by exactly one UTF-8 JSON value
- Maximum frame: 65,536 bytes

Unknown fields, unknown enum values, invalid UTF-8, empty frames, partial frames and oversized frames
are protocol failures. Raw frames are never logged. Every failure at this boundary becomes a
sanitized fail-closed result; the decision pipeline records it as `VETO_DENIED`.

## Connection and identity

The socket is a direct child of an absolute runtime directory owned by Viper's effective UID with
mode exactly `0700`. The socket must be a real Unix socket owned by the same UID and grant no group
or other permissions. After connecting, the client obtains kernel peer credentials and requires the
provider UID to equal Viper's effective UID. Filesystem checks do not replace peer credentials or
HMAC authentication.

Defaults are 250 ms for connect and 1,000 ms for the complete post-connect exchange. Neither value
may exceed five seconds. There is no automatic retry.

## One-shot authenticated exchange

Each connection carries exactly one decision and then the provider closes its write side:

1. `client_hello`: protocol, fresh session ID and 256-bit client nonce.
2. `server_challenge`: matching session ID and fresh 256-bit provider nonce.
3. `client_authentication`: ACTIVE key ID and client-role HMAC over protocol, key ID, session ID,
   both nonces and role.
4. `server_authentication`: matching key ID and provider-role HMAC over the same bound values.
5. `decision_request`: request/proposal/trace IDs, timestamp, normalized tool and arguments, and
   versioned Tool Guard evidence including policy digest.
6. `decision_response`: matching request and proposal IDs, a closed verdict enum, stable reason code
   and bounded sanitized explanation.
7. Clean EOF. Any byte after the first response is a duplicate/trailing-frame failure.

New connections authenticate only with the ACTIVE key. Existing-session grace behavior remains in
the keyring contract for a future explicitly persistent protocol; v1 one-shot decisions do not use
it. `viper-seed::credential::load_keyring` loads one `VIPER_SEED_KEY_V1` record from an inherited
reader: key ID and 32-byte secret encoded as 64 lowercase hex characters, each on its own line, with
a final newline and a 256-byte ceiling. It rejects malformed/extra data with sanitized errors and
zeroizes temporary buffers. The caller must provide a private, finite file-like descriptor and
close it after loading. Secrets are never accepted in command arguments, environment variables,
JSON or trajectory. Rotation/provisioning remains outside this v1 one-shot client slice.

## Current test evidence

The deterministic fake provider covers a successful authenticated verdict, response identifier
substitution, duplicate response data, invalid provider HMAC, unsafe directory permissions, full
handshake timeout, byte-at-a-time fragmentation, oversized frames and unknown JSON fields. A Linux
cross-UID integration test uses `setpriv` to connect from UID 65534 and proves the kernel peer-UID
check rejects the real connection; run it under root in CI. Unprivileged local test runs skip that
integration branch and still exercise the UID comparison unit test. The cross-UID integration case
was executed successfully in an isolated network-disabled root container on 2026-10-19.
