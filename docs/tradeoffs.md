# Tradeoffs — identity-provider

Core tradeoffs live in the README §6. This doc captures smaller decisions made
during implementation, and items explicitly flagged for later review.

## Resolved (captured in README)

- **JWT access tokens, no introspection** — README §6
- **Outbox pattern for FGA sync** — README §6
- **Refresh token rotation, Level 2** (no reuse detection yet) — README §6
- **Separate Postgres databases for IdP and OpenFGA** — README §6
- **Basic HTML for login + consent, no admin UI** — README §6

## Pending / to be decided during build

### Signing algorithm: Ed25519 vs RS256
- **Currently leaning:** Ed25519 (JOSE alg: `EdDSA`). Smaller keys, faster signing, modern cryptography
- **Counterargument:** RS256 is the de-facto standard. Some clients/libs may only support RS256
- **Decision point:** pick when implementing `internal/tokens/keys.go`. Probably Ed25519 with a note that switching to RS256 is a config change

### Session storage: Postgres vs Redis
- **Currently:** Postgres (`sessions` table)
- **Pro Postgres:** no extra service dependency for IdP
- **Pro Redis:** TTL is native, writes are cheaper at scale
- **Decision:** Postgres for now. Revisit if session writes become a hot path (they won't at our scale)

### JWT lifetime
- **Access token:** 15 min
- **ID token:** 5 min (clients shouldn't hold these long)
- **Refresh token:** 30 days
- **Auth code:** 60 seconds (RFC 6749 recommends ≤60s)
- **Lifetimes are env-configurable**; above are defaults

### Consent: per-scope vs per-client?
- **Chose:** per-client + scope set. If client requests `[a, b]` now and `[a, b, c]` later, user is re-prompted for consent
- **Alternative:** "prompt once per scope, globally" — rejected, loses client-context meaning

### Outbox worker batch size + sleep
- **Initial:** 100 rows per batch, 1s sleep on empty. Adjust based on observed lag
- **Stretch:** `LISTEN/NOTIFY` on the outbox table so the worker wakes immediately on new rows instead of polling

### Secret/KEK storage
- **Chose for lab:** env var `JWT_SIGNING_KEY_ENCRYPTION_KEY` (random 32 bytes, hex-encoded). AES-GCM to wrap private signing keys at rest
- **Rejected:** cloud KMS (out of scope). Vault integration (out of scope)
- **Comment:** this is deliberately a toy — a real IdP would never store private keys this way

### Client secrets: store hashed or encrypted?
- **Chose:** hashed (argon2id). Clients authenticate by sending the secret, we hash and compare
- **Alternative:** encrypted and decrypted for comparison
- **Why hashed:** we never need the plaintext after registration, same reason passwords are hashed

### Password hashing
- **Chose:** argon2id with memory=64MB, iterations=3, parallelism=4. Default parameters from OWASP 2024 guidance
- **Stretch:** migrate hashes on login when parameters change

## Revisit later (tracked so they don't get lost)

- **Refresh token reuse detection** — Level 3. Stretch goal; schema supports it (rotated_from). Promote if implementing production-shape auth.
- **Introspection endpoint** — if we ever need revocation latency <expiry-time, add RFC 7662 /introspect + caching layer on demo-api
- **mTLS client authentication** — public clients PKCE-only is fine, but confidential clients might want mTLS over client_secret (RFC 8705)
- **DPoP / sender-constrained tokens** — one endpoint on demo-api to feel this; tracked as stretch in learning_objectives
- **Dynamic client registration (RFC 7591)** — skipped; admin UI would come first
- **Consent revocation UI** — no way for users to revoke consent without admin; out of scope
- **Auto-rotate signing keys on schedule** — manual-only for now
