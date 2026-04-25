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
- OAuth handlers (`internal/oauth` — authorize, token, refresh-grace cache)
- OIDC handlers (`internal/oidc` — discovery, jwks, userinfo)
- Consent tracking (`internal/consent`) with admin-scope filtering for non-admin users
- Outbox writer (`internal/outbox` — `Enqueue(ctx, tx, event)` insists on a `pgx.Tx` so atomicity is compile-time enforced)
- Admin JSON API (`internal/http/admin`) — bearer-authenticated REST surface mounted at `/admin/api/*`, gated by `admin` scope + `is_admin` flag (defense in depth against post-issue demotion)

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
- **Row-level locking** inside a transaction means if the worker crashes after FGA write but before commit, another worker re-processes — idempotency on FGA tuple writes (`OnDuplicateWrites=ignore` flag) makes this safe (writing the same tuple twice is a no-op)
- **attempt_count + last_error** let us backoff poison-pill events rather than infinite-retry; rows beyond `OUTBOX_MAX_ATTEMPTS=5` drop out of the claim query and surface as "failed" in the admin UI
- **Per-tuple coalescing across a batch** in `cmd/outbox-worker`: if a batch contains both Write and Delete on the same `(user, relation, object)` tuple, we collapse based on first/last op to avoid hitting `cannot_allow_duplicate_tuples_in_one_request` from FGA
- Translation: `internal/outbox/translate.go` (event → tuple ops)

### docs-api (`cmd/docs-api`)
Separate binary on `:8083` (OpenFGA occupies host :8081 for HTTP and
:8082 for gRPC per docker-compose.yml). Deliberately minimal business
logic; serves an in-memory doc + folder corpus so the SPA can exercise
the full triangle (browser ↔ IdP ↔ resource server) over realistic data.

```
middleware: authenticate (cmd/docs-api/auth.go)
  - parse Authorization: Bearer <token>
  - call tokens.Verifier.Verify(ctx, raw) — JWKS cache resolves keys per issuer
  - populate request ctx with verified *AccessClaims
middleware: requireScope("read:docs" | "write:docs")
  - 403 if scope not present in claims.Scope
handler: resource (cmd/docs-api/handlers.go)
  - call resolvePermission(user, type, id) — runs up to 3 FGA Checks
    (owner / editor / viewer) highest-first, short-circuit on hit
  - 404 (not 403) if no tier — hides existence from non-viewers
  - response includes "permission" field so the SPA can show/hide
    edit/delete affordances without round-tripping
```

Configured with (all env-driven):
- `TRUSTED_ISSUERS` — comma-separated list of issuer URLs. Each has its JWKS
  fetched + cached independently. This is where the multi-issuer lesson lives.
- `OPENFGA_API_URL`, `OPENFGA_STORE_ID`, `OPENFGA_AUTHORIZATION_MODEL_ID` — OpenFGA endpoint + store/model IDs (printed by `idp fga init`)
- `REQUIRED_AUD` — the audience this API accepts. **Lab shortcut**: the IdP issues `aud=<client_id>`, so set this to the client id (e.g. `localdev`). Production IdPs would issue per-resource audiences via RFC 8707 resource indicators.
- `ALLOWED_ORIGINS` — CORS origins. Set to `http://localhost:5173` for the Vite dev server; not strictly needed when going through the dev proxy but useful for direct-origin testing.
- `DOCS_SEED_{ALICE,BOB,CAROL}` — the user UUIDs to bake into the seeded FGA tuples; the corpus has deterministic IDs but the *people* in it come from the running IdP.

### Admin JSON API (`internal/http/admin`)
Hosted by the IdP itself under `/admin/api/*`. Purpose: surface the same
operations as the `idp users|groups|outbox` CLI subcommands as JSON
endpoints the admin SPA can call.

Defense-in-depth chain in `Authenticate`:
1. Bearer parse + `tokens.Verifier.Verify` (reuses the same `selfVerifier`
   the `/userinfo` handler uses — no JWKS HTTP fetch needed; the IdP
   verifies its own tokens locally via `KeyStoreResolver`)
2. Token's `scope` claim must contain `admin`
3. Token's `sub` (user UUID) must have `is_admin=true` in the DB

The third check catches the case where someone is demoted between consent
and the API call: the token still validates and has the scope, but the
runtime DB lookup fails. Without this, demotion wouldn't take effect
until the access token expired.

The consent flow has a complementary upstream gate (`internal/http/consent.go`):
when a non-admin user requests `admin` scope at `/authorize`, the consent
handler silently filters it out before granting. The user gets a token
without `admin` in scope rather than an error page — better UX than "you
can't have admin", since most of the time the SPA just requested a
superset and doesn't actually need it.

### Refresh-token reuse grace (`internal/oauth/refresh_grace.go`)
30-second in-memory cache keyed by `sha256(refresh_token_plaintext)`. On
the first successful rotation, the marshaled `tokenResponse` is cached
(including the rotated refresh_token). If the same plaintext is presented
again within the window, the IdP returns the cached body verbatim —
both racing clients converge on the same access_token + new refresh_token.

Solves the canonical browser-SPA race: React StrictMode double-mounts an
effect (in dev), tab-focus fires `accessTokenExpiring` while a parallel
fetch already kicked off renewal, network retry resends a still-in-flight
refresh request. Without the grace window, the second presentation hits
strict-rotation invalidation and the SPA surfaces "refresh token invalid"
even though one of the two calls succeeded.

In-memory only; lost on IdP restart. Acceptable cost — a 30s window
through a restart is rare and the worst case is one client gets
`invalid_grant` and re-auths.

### web SPA (`web/`)
Vite + React 18 + TypeScript (strict) + Tailwind v4. Two route trees in
one app:
- `/`, `/callback`, `/docs/*` — docs product
- `/admin/{,users,groups,outbox}` — IdP admin, scope-gated

Auth is `react-oidc-context` over `oidc-client-ts`. Tokens stored
in-memory only (no localStorage / sessionStorage). Silent renewal via
the refresh-token grant; the IdP's grace window absorbs the client
race.

Dev proxy (`vite.config.ts`) rewrites `/api/docs` → `:8083/` and
`/api/admin` → `:8080/admin/api/` so the SPA calls same-origin in dev.
Production deploys can keep the cross-origin split (`ALLOWED_ORIGINS` on
each backend) or front-proxy both behind one nginx.

Permission tiers (owner / editor / viewer) come back on every doc/folder
response from docs-api as a `permission` field; the SPA uses
`canEdit(perm)` / `canDelete(perm)` helpers to show/hide affordances.
Backend re-checks on every mutation — UI gating is for UX, not security.

### OpenFGA
External OSS service run via docker-compose (`openfga/openfga:v1.14.2`,
postgres storage backend). We don't modify it; we're learning the
consumer-correct patterns. Pinned to v1.14.2 because v1.10+ honors the
`OnDuplicateWrites=ignore` / `OnMissingDeletes=ignore` flags the worker
sends; v1.9.x silently ignored them and returned hard errors on benign
duplicate writes / missing deletes.

Two OpenFGA APIs we use:
- `Write` (called by outbox-worker) to write/delete tuples (one atomic
  request can carry both)
- `Check` (called by docs-api + admin API handlers) to authorize specific
  operations

Optional later: `Expand` for debug/explainability, `BatchCheck` for
performance, `ListObjects` to filter list endpoints at the authz tier.

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
