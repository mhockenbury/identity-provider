# Architecture — identity-provider

Deeper component breakdown. README has the top-level view; this doc expands
per-component and per-flow.

## Components

### idp (`cmd/idp`)
Stateful HTTP server on `:8080`. Routes live in `internal/http`. Owns:
- User identity (`internal/users`)
- Client registry (`internal/clients`)
- Token lifecycle (`internal/tokens` — JWT sign, refresh rotation)
- Key management (`internal/tokens/keys.go`)
- OAuth handlers (`internal/oauth` — authorize, token)
- OIDC handlers (`internal/oidc` — discovery, jwks, userinfo)
- Consent tracking (`internal/consent`)
- Outbox writer (`internal/outbox` — `EnqueueEvent(tx, event)` used by handlers that mutate identity)

Session handling for login/consent: UNSIGNED cookies carrying only the session ID,
HttpOnly, SameSite=Lax, 12h absolute TTL. Server resolves the ID via Postgres
on every request — a forged ID fails the DB lookup, so "unforgeable session"
holds without HMAC. Session data is session_id → user_id + expires_at, stored
in Postgres (`sessions` table, migration 0001).

Cookie signing is a deliberate simplification; a real IdP would HMAC-sign for
defense in depth + to carry additional data without a DB hit. Tradeoff noted
in `internal/users/sessions.go` package comment and `docs/tradeoffs.md`.

### outbox-worker (`cmd/outbox-worker`)
Single binary. Loop:
```
while not shutting down:
    rows = SELECT id, event_type, payload
           FROM fga_outbox
           WHERE processed_at IS NULL
           ORDER BY id
           FOR UPDATE SKIP LOCKED
           LIMIT BATCH_SIZE
    for each row:
        translate(event_type, payload) → [tuple_ops]
        call OpenFGA Write API with tuples
    UPDATE fga_outbox SET processed_at=now() WHERE id IN (...)
    COMMIT
    if rows was empty: sleep BLOCK_DURATION
```

Key behaviors:
- **SKIP LOCKED** means multiple worker instances can safely run; each claims a disjoint set of rows
- **Row-level locking** inside a transaction means if the worker crashes after FGA write but before commit, another worker re-processes — idempotency on FGA tuple writes makes this safe (writing the same tuple twice is a no-op)
- **attempt_count + last_error** let us backoff poison-pill events rather than infinite-retry
- Translation table from event_type → FGA ops lives in `internal/fga/translations.go`

### docs-api (`cmd/docs-api`)
Separate binary on `:8083` (OpenFGA occupies host :8081 for HTTP and
:8082 for gRPC per docker-compose.yml). Deliberately minimal business
logic; exists to make the downstream-service lessons concrete.

```
middleware: authenticate
  - parse Authorization: Bearer <token>
  - parse JWT header, extract kid + alg
  - look up (iss, kid) in JWKS cache
  - on miss: GET <iss>/.well-known/jwks.json, refresh cache
  - verify signature, exp, nbf, iss (against allowlist), aud
  - populate request ctx with sub, scopes
middleware: require_scope(scope)
  - 403 if scope not present
handler: resource
  - call OpenFGA Check(user, relation, object)
  - 403 if not allowed
```

Configured with:
- `TRUSTED_ISSUERS` — comma-separated list of issuer URLs. Each has its JWKS
  fetched + cached independently. This is where the multi-issuer lesson lives.
- `FGA_API_URL`, `FGA_STORE_ID` — OpenFGA endpoint
- `REQUIRED_AUD` — the audience this API accepts

### OpenFGA
External OSS service run via docker-compose (`openfga/openfga:latest`, postgres
storage backend). We don't modify it; we're learning the consumer-correct patterns.

Two OpenFGA APIs we'll use:
- `Write` (called by outbox-worker) to write tuples
- `Check` (called by docs-api handlers) to authorize specific operations

Optional later: `Expand` for debug/explainability, `BatchCheck` for performance.

## Authorization code + PKCE, in detail

The flow I keep in my head vs what the spec actually says — this section
reconciles the two.

### Parameters the client sends to /authorize

| Parameter | Purpose | Where it ends up |
|-----------|---------|------------------|
| `response_type=code` | declares auth code flow | validated, discarded |
| `client_id` | which client is asking | verified against clients table |
| `redirect_uri` | where to send the code back | must exactly match a registered uri |
| `scope` | space-separated scope list | shown on consent, encoded in tokens |
| `state` | CSRF token, client remembers and verifies | echoed back in redirect |
| `code_challenge` | SHA-256 hash of code_verifier | stored in auth_codes, checked at /token |
| `code_challenge_method` | "S256" (we only accept S256) | stored but validated to S256 only |
| `nonce` | mitigates ID token replay | echoed in ID token's nonce claim |

### Validation on /authorize
1. Client exists and `response_type=code` is in allowed_grants
2. `redirect_uri` is exactly listed in client's allowed URIs (no fuzzy match)
3. `scope` is subset of client's allowed_scopes
4. `code_challenge_method=S256` (reject plain; refuse silently-weak crypto)
5. User is logged in (else redirect to /login, then back here)
6. User has consented to these scopes for this client (else redirect to /consent)

### What /token does in detail
1. Authenticate the client (basic auth or client_secret_post for confidential; PKCE-only for public)
2. Look up the auth_code; reject if expired or already used_at
3. Compute SHA-256(code_verifier), compare to stored code_challenge — CONST-TIME compare
4. Mark code as used (UPDATE ... SET used_at=now() ... WHERE used_at IS NULL — single-row mutual exclusion via the DB)
5. Issue access token (JWT with sub, aud, exp, iat, jti, scope, iss)
6. Issue ID token (JWT with additional nonce, auth_time, and user claims)
7. Issue refresh token (opaque; row inserted with expires_at, client_id, scopes)

### What happens on refresh
1. Authenticate the client (same as above)
2. Look up refresh token; verify not expired, not revoked_at, matches client_id
3. Revoke the old refresh_token (UPDATE ... SET revoked_at=now())
4. Insert a new refresh_token row with `rotated_from` = old.id
5. Issue a new access token (same sub, same scopes — or subset if client requested scope downgrade)
6. Return the new pair

### What happens on consent mutation
When a user grants consent (new or modified):
```
BEGIN TX
  UPSERT consents (user_id, client_id, scopes)
  INSERT fga_outbox (event_type="consent_granted", payload={...})
COMMIT
```
The outbox writes nothing to FGA for consent itself — but we capture the event
for audit log integration later (stretch).

### What happens on group membership change (admin action)
```
BEGIN TX
  INSERT group_memberships (user_id, group_id)
  INSERT fga_outbox (event_type="group_membership_added", payload={user_id, group_id})
COMMIT
```

Outbox worker then:
- Translates event_type="group_membership_added" → OpenFGA Write with tuple `(user:alice, member, group:editors)`
- Applies

## Key management (`internal/tokens/keys.go`)

RSA-2048 or Ed25519 keys. Leaning Ed25519 for size + speed; faster signing,
smaller JWKS. (JOSE standard name: `EdDSA`.)

Keys live in `signing_keys` table:
- `kid` — unique identifier in JWTs and JWKS
- `public_key_jwk` — bytes, the JWK serialization
- `private_key_enc` — encrypted with a KEK from `JWT_SIGNING_KEY_ENCRYPTION_KEY` env var (symmetric, AES-GCM); simple, not a real KMS
- `activated_at` — null means not-yet-used; set when this key becomes the signing key
- `retired_at` — null means still in JWKS (for verification); set when key drops from JWKS

Key rotation:
1. Generate new key, insert with `activated_at=null`
2. Mark as active: set `activated_at=now()` on new, leave old's `retired_at=null` so it's still in JWKS for verification
3. After 2x token-lifetime, retire old: set `retired_at=now()` — drops from JWKS
4. Clients see new key in JWKS on next cache-miss

JWKS endpoint returns all rows where `retired_at IS NULL`. Signing uses the
one where `activated_at IS NOT NULL AND retired_at IS NULL` and `activated_at`
is most recent.

No admin UI for rotation in core; exposed via CLI subcommand (stretch) or
SQL when we need it.

## Error handling philosophy

OAuth 2.0 has specific error response shapes. We honor them.

- `/authorize` errors → redirect to `redirect_uri` with `?error=...&error_description=...&state=...` when we have a valid redirect_uri; otherwise render an HTML error page
- `/token` errors → JSON `{error, error_description}` with appropriate status (400 for most, 401 for invalid_client)
- `/userinfo` errors → `WWW-Authenticate` header per RFC 6750

docs-api errors → plain JSON `{error}` for simplicity (it's a lab API).

## Testing approach

- **Unit tests:** pure functions — PKCE verify, JWT build, scope logic, outbox event translation
- **Integration tests:** hit a real Postgres + real OpenFGA via docker-compose. Skip cleanly if unreachable (same pattern as url-shortener). **No mocked DBs** — matches matt's standing feedback.
- **E2E smoke:** oidc-client-ts in a browser, scripted via Playwright. Demo API called with the resulting token. This is the ultimate correctness test — if a mainstream OIDC client completes the full flow, we know the protocol implementation is right.
- **Forged token test:** docs-api explicitly rejects a token signed with a non-trusted key
- **Key rotation test:** simulate the IdP rotating signing keys mid-flight; docs-api's JWKS cache refreshes on unknown kid
