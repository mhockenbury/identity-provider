# Architecture — identity-provider

Per-component breakdown. README has the top-level view; this expands it.

## Components

### idp (`cmd/idp`)

HTTP server on `:8080`. Owns:
- User identity (`internal/users`), client registry (`internal/clients`)
- Token lifecycle and key management (`internal/tokens`)
- OAuth handlers (`internal/oauth` — authorize, token, refresh-grace)
- OIDC handlers (`internal/oidc` — discovery, jwks, userinfo)
- Consent (`internal/consent`) with admin-scope filtering for non-admins
- Outbox writer (`internal/outbox` — `Enqueue(ctx, tx, event)` insists on a `pgx.Tx` for compile-time atomicity)
- Admin JSON API (`internal/http/admin`) at `/admin/api/*`, gated by `admin` scope + `is_admin` flag (defense in depth against post-issue demotion)

**Sessions.** Login/consent use unsigned cookies carrying only the session ID (HttpOnly, SameSite=Lax, 12h TTL). Server resolves via Postgres on every request — a forged ID fails the lookup. Cookie HMAC-signing is a deliberate simplification; a real IdP would sign for defense in depth + to carry data without a DB hit. Noted in `internal/users/sessions.go` and `docs/tradeoffs.md`.

### outbox-worker (`cmd/outbox-worker`)

```
loop:
    rows = SELECT ... FROM fga_outbox
           WHERE processed_at IS NULL
           ORDER BY id
           FOR UPDATE SKIP LOCKED
           LIMIT BATCH_SIZE
    for each row: translate event → tuple ops
    call OpenFGA Write API
    UPDATE fga_outbox SET processed_at=now() WHERE id IN (...)
    COMMIT
    if rows empty: sleep BLOCK_DURATION
```

- **SKIP LOCKED** — multiple workers safely partition rows.
- **Idempotent on replay** — crash after FGA write but before commit re-processes; FGA `OnDuplicateWrites=ignore` makes that safe.
- **Poison-pill quarantine** — `attempt_count` + `last_error`; rows past `OUTBOX_MAX_ATTEMPTS=5` drop out of the claim query and surface as failed in the admin UI.
- **Per-tuple coalescing across a batch** — collapse W+D on the same `(user, relation, object)` to avoid `cannot_allow_duplicate_tuples_in_one_request`.
- Translation lives in `internal/outbox/translate.go`.

### docs-api (`cmd/docs-api`)

Separate binary on `:8083`. Deliberately minimal business logic; serves an in-memory doc + folder corpus so the SPA can exercise the full triangle (browser ↔ IdP ↔ resource server).

```
authenticate (auth.go)
  - parse Authorization: Bearer
  - tokens.Verifier.Verify — JWKS cache resolves keys per issuer
  - populate ctx with verified *AccessClaims
requireScope("read:docs" | "write:docs")
  - 403 if scope missing
resolvePermission (handlers.go)
  - up to 3 FGA Checks (owner / editor / viewer), highest-first, short-circuit
  - 404 (not 403) on no-tier — hides existence
  - response includes "permission" so the SPA gates affordances client-side
    (backend re-checks on every mutation)
```

Env config:
- `TRUSTED_ISSUERS` — comma-separated; each gets its own JWKS cache. Multi-issuer lesson lives here.
- `OPENFGA_API_URL`, `OPENFGA_STORE_ID`, `OPENFGA_AUTHORIZATION_MODEL_ID` — printed by `idp fga init`.
- `REQUIRED_AUD` — the resource server's identity (e.g. `docs-api`). Per RFC 8707, the access token's `aud` claim identifies the *resource server*, not the OAuth client. The SPA passes `resource=docs-api` at `/authorize`; the IdP stamps that into `aud`; docs-api requires the match.
- `ALLOWED_ORIGINS` — CORS for direct-origin testing (dev proxy makes this optional).
- `DOCS_SEED_{ALICE,BOB,CAROL}` — user UUIDs to bake into the seeded FGA tuples; the corpus has deterministic IDs but the *people* come from the running IdP.

### Admin JSON API (`internal/http/admin`)

Three-layer gate in `Authenticate`:
1. Bearer parse + `tokens.Verifier.Verify` (uses `KeyStoreResolver` — IdP verifies its own tokens via Postgres, no JWKS HTTP fetch).
2. Token scope must contain `admin`.
3. Token `sub` must have `is_admin=true` in DB.

Layer 3 catches demotion-between-consent-and-call. Without it, demotion wouldn't take effect until the access token expired.

Complementary upstream gate in `internal/http/consent.go`: when a non-admin requests `admin` scope at `/authorize`, the consent handler silently filters it out — better UX than an error page, since most SPAs request a superset.

### Refresh-token reuse grace (`internal/oauth/refresh_grace.go`)

30s in-memory cache keyed by `sha256(refresh_token_plaintext)`. On the first successful rotation, the marshaled `tokenResponse` is cached. A second presentation within the window returns the cached body verbatim — both racing clients converge on the same access_token + new refresh_token.

Solves the canonical browser-SPA race: StrictMode double-mount, tab refocus mid-renewal, network retry. Without it, the second presentation hits strict-rotation invalidation and the SPA shows "refresh token invalid" even though one of the calls succeeded.

In-memory only; lost on restart. Worst case: one client gets `invalid_grant` and re-auths.

### web SPA (`web/`)

Vite + React 19 + TypeScript (strict) + Tailwind v4. Two route trees in one app:
- `/`, `/callback`, `/docs/*` — docs product
- `/admin/{,users,groups,outbox,clients}` — IdP admin, scope-gated

Auth via `react-oidc-context` over `oidc-client-ts`. Tokens in-memory only (no localStorage / sessionStorage). Silent renewal via refresh-token grant; the IdP's grace window absorbs the client race.

Dev proxy (`vite.config.ts`) rewrites `/api/docs` → `:8083/` and `/api/admin` → `:8080/admin/api/` so the SPA calls same-origin in dev.

Permission tiers (owner / editor / viewer) come back on every doc/folder response from docs-api as a `permission` field; `canEdit(perm)` / `canDelete(perm)` show/hide affordances. UI gating is for UX, not security.

### OpenFGA

External OSS service via docker-compose, pinned to `openfga/openfga:v1.14.2` (v1.10+ honors `OnDuplicateWrites=ignore` / `OnMissingDeletes=ignore`; v1.9.x silently ignored them and returned hard errors on benign duplicates).

We use `Write` (worker) and `Check` (docs-api + admin handlers). `Expand` / `BatchCheck` / `ListObjects` are optional later.

## Authorization code + PKCE, in detail

### /authorize parameters

| Parameter | Purpose | Where it ends up |
|-----------|---------|------------------|
| `response_type=code` | declares auth code flow | validated, discarded |
| `client_id` | which client | verified against clients table |
| `redirect_uri` | callback target | exact match against registered list |
| `scope` | space-separated | shown on consent, encoded in tokens |
| `state` | client CSRF token | echoed back |
| `code_challenge` | SHA-256(code_verifier) | stored, checked at /token |
| `code_challenge_method` | `S256` only | reject `plain` |
| `nonce` | ID token replay mitigation | echoed in ID token |
| `resource` | RFC 8707 — resource server identity | becomes the access token's `aud` |

### /authorize validation

1. Client exists; `response_type=code` is in `allowed_grants`
2. `redirect_uri` exact-match against client's allowlist
3. `scope` ⊆ `allowed_scopes` (and non-empty — explicit-scope required)
4. `resource` ∈ `client.resources` (and non-empty — explicit-resource required, RFC 8707)
5. `code_challenge_method=S256`
6. User logged in (else /login)
7. Consent present for these scopes (else /consent)

### /token

1. Client auth (basic/post for confidential; PKCE-only for public)
2. Look up auth code; reject if expired or `used_at IS NOT NULL`
3. SHA-256(code_verifier) const-time compare to stored challenge
4. `UPDATE auth_codes SET used_at=now() WHERE used_at IS NULL` — single-row mutex
5. Issue access JWT — `aud=<resource>` (from auth code), `sub`, `exp`, `iat`, `jti`, `scope`, `iss`, `client_id`
6. Issue ID JWT — `aud=<client_id>` (per OIDC Core; ID tokens are *for* the client to consume), `nonce`, `auth_time`, user claims
7. Insert refresh token row (carries the resource so rotation issues access tokens with the same `aud`)

### /token (refresh)

1. Client auth
2. Look up refresh token; verify not expired/revoked, matches `client_id`
3. Revoke old: `UPDATE ... SET revoked_at=now()`
4. Insert new with `rotated_from = old.id`
5. Issue new access token (same scopes, or subset on downgrade)

### Consent mutation

```sql
BEGIN;
  UPSERT consents (user_id, client_id, scopes);
  INSERT fga_outbox (event_type='consent_granted', payload=...);
COMMIT;
```

The outbox row writes nothing to FGA today; captured for future audit-log integration.

### Group membership change

```sql
BEGIN;
  INSERT group_memberships (user_id, group_id);
  INSERT fga_outbox (event_type='group_membership_added', payload={user_id, group_id});
COMMIT;
```

Worker translates `group_membership_added` → OpenFGA Write `(user:alice, member, group:editors)`.

## Key management (`internal/tokens/keys.go`)

Ed25519 (`EdDSA`). 32-byte keys, fast deterministic signing, minimal JWKS payload.

`signing_keys` row:
- `kid` — JWT header + JWKS identifier
- `public_key_jwk` — JWK serialization
- `private_key_enc` — AES-GCM under `JWT_SIGNING_KEY_ENCRYPTION_KEY` (`kid` bound as AAD)
- `activated_at` / `retired_at` — derive PENDING/ACTIVE/RETIRED state

Rotation:
1. Generate, insert with `activated_at=null`
2. Activate new (`activated_at=now()`); leave old's `retired_at=null` so it stays in JWKS for verification
3. After 2× token-lifetime, retire old (`retired_at=now()`) — drops from JWKS

JWKS serves all rows where `retired_at IS NULL`. Signing uses the most-recent active. Partial unique index `signing_keys_one_active_idx` enforces "at most one active" at the DB layer. CLI: `idp keys {generate,activate,retire}`.

## Error handling

- `/authorize` → redirect to `redirect_uri` with `?error=...&error_description=...&state=...` if the redirect is valid; HTML error page otherwise
- `/token` → JSON `{error, error_description}`; 400 for most, 401 for `invalid_client`
- `/userinfo` → `WWW-Authenticate` per RFC 6750
- docs-api → plain JSON `{error}` (lab simplification)

## Testing approach

- **Unit:** pure functions — PKCE verify, JWT build, scope logic, outbox translation
- **Integration:** real Postgres + real OpenFGA via docker-compose; skip-on-unreachable. No mocked DBs.
- **Smoke:** `scripts/dev_flow.sh` (curl) + `scripts/docs_smoke.sh` (full triangle). Browser flow validated against `oidc-client-ts` via the SPA.
- **Forged-token test:** docs-api rejects a token signed by an untrusted key.
- **Key-rotation test:** simulate IdP rotation mid-flight; docs-api JWKS cache refetches on unknown `kid`.
