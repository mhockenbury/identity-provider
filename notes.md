# identity-provider — Notes

Subproject-local notes: decisions during implementation, commands, references.
The README is the design doc; this file is the working log.

## Current state (as of layer 7 complete)

Working HTTP surface — all OAuth + OIDC endpoints live:

| Endpoint | Status | Layer |
|----------|--------|-------|
| `GET /.well-known/openid-configuration` | ✓ | 4 |
| `GET /.well-known/jwks.json` | ✓ | 4 |
| `GET /authorize` | ✓ | 5 |
| `GET + POST /login` | ✓ | 5 |
| `GET + POST /consent` | ✓ | 5 |
| `POST /token` (authorization_code + refresh_token grants) | ✓ | 6 |
| `GET /userinfo` | ✓ | 7 |
| `GET /healthz` | ✓ | 4 |

End-to-end smoke test (`make dev-flow`) exercises all of them in one script:
GET /authorize → redirect to /login → POST /login → redirect to /consent → POST approve → redirect with code → POST /token → GET /userinfo → bonus refresh rotation.

Pending:
- **Layer 8** — outbox writer hooks (inside identity-mutation transactions) + `cmd/outbox-worker` draining to OpenFGA. The novel "claims-to-tuples" twist.
- **Layer 9** — docs-api (separate binary validating JWTs against JWKS, enforcing FGA).
- **Stretches** — WebAuthn, DPoP, refresh reuse detection, RFC 8693 token exchange, **client-app/SPA integration** (catch-all callback listener or a real oidc-client-ts SPA; currently the browser flow dead-ends at `localhost:5173/callback` with "Unable to connect" because no client exists).

## Decisions (during scaffolding)

- **Go module path:** `github.com/mhockenbury/identity-provider`
- **OpenFGA version:** pinned to `openfga/openfga:v1.9.4`. Compose services exist but not yet used (layer 8+).
- **OpenFGA storage backend:** Postgres (separate DB from IdP), mirrors realistic deployment.
- **Go version target:** 1.25 (matches url-shortener; auto-bumped by pgx/v5 dep).
- **Binaries live on host** during dev; compose runs only the databases + OpenFGA.
- **Session storage:** Postgres (`sessions` table), not Redis — keeps compose minimal.
- **Scope for seed:** one public OAuth client `localdev` seeded via `scripts/seed_client.sql`, PKCE-only.

## Decisions (during implementation)

Big-pattern choices worth recording so future sessions don't re-derive them.

### Crypto + keys

- **Signing algorithm:** Ed25519 / `EdDSA`. Modern, 32-byte keys, fast; one alg only (no RS256 fallback).
- **KEK:** env-var-loaded 32-byte symmetric, AES-256-GCM envelope, `kid` bound as AAD so row-mix bugs fail loud. In production this would be a KMS; the `KEK` interface is deliberately small so swapping is trivial.
- **Signing-key state machine:** 3 states derived from timestamps (PENDING / ACTIVE / RETIRED). Partial unique index `signing_keys_one_active_idx` enforces "at most one active" at the DB, not in code — a race or code bug can't produce two actives.
- **Verifier resolver choice:** two implementations of `KeyResolver` — `KeyStoreResolver` (internal, hits Postgres directly, no HTTP) for the IdP verifying its own tokens at `/userinfo`; downstream services (future docs-api) will implement with an HTTP-fetched JWKS cache.

### Password + client secret hashing

- **argon2id** encoded in PHC format with the params baked into the hash. Future param bumps don't invalidate existing hashes.
- **Client secrets use the same primitive** as user passwords — both are "bearer secret at rest." Avoids two hash stacks. If we rotate, they rotate together.

### Session design

- **Session cookie is unsigned.** Carries only the session ID (UUID); server looks up Postgres on every request. A forged ID fails the DB lookup. Production would HMAC-sign for defense in depth + to carry data without DB hits; flagged in `internal/users/sessions.go`.
- **12-hour absolute lifetime**, no sliding extension.
- **`WithSession` middleware is advisory**, not gating — populates request ctx with `users.Session` if present, passes through silently if not. Handlers that require auth redirect to /login themselves.
- **Stale cookies NOT cleared** by the middleware. `/login` overwrites on next auth; clearing mid-middleware would add a Set-Cookie to every anonymous request.

### Authorization codes

- **Plaintext in DB** (not hashed) — they have 60s TTL + single-use, hashing adds no meaningful security and complicates the lookup path. Refresh tokens (30d, reusable until rotated) DO hash.
- **Atomic single-use via `UPDATE ... WHERE used_at IS NULL RETURNING`**. 8-goroutine race test: 1 succeeds, 7 get `ErrCodeAlreadyUsed`.
- **Client mismatch check happens BEFORE the claim.** A wrong client does NOT burn the code; the legitimate holder can still redeem.

### Refresh tokens

- **SHA-256 hashed at rest** — 30-day lifetime means a DB dump is worth defending against, but the 256-bit random input doesn't need argon2.
- **Level 2 rotation** (no reuse detection yet): each rotate marks old revoked, issues new, links via `rotated_from`. Family-invalidation on reuse (Level 3) is a tracked stretch; the schema supports it.
- **Serialized via `BEGIN + SELECT FOR UPDATE`.** Concurrent-rotate test: 1 wins, 7 get `ErrRefreshRevoked`.
- **Scope downgrade allowed** (RFC 6749 §6: refresh MAY return subset). Scope upgrade rejected (MUST NOT grant new).

### Consent

- **Sorted + deduped scopes in storage.** `HasScopes(a,b) == HasScopes(b,a)`.
- **Subset checks at request time.** Consenting to `[a,b,c]` means requesting `[a]` passes without re-prompt; requesting `[a,d]` re-prompts.
- **Per (user, client)** — single row. Re-prompts on scope-set change; last grant wins.

### HTTP / handlers

- **Service interface lives in `internal/http`, not `internal/oauth`** (Go idiom: consumer-defined interfaces). Handler tests fake without pulling pgx.
- **Authorize handler: plain 400 vs redirect-with-error.** Client/redirect_uri validation failures render a plain error page — we CANNOT redirect errors to an untrusted redirect_uri. All other validation errors redirect back per RFC 6749 §4.1.2.1.
- **`/token` back-channel, no session, no CSRF.** Client credentials authenticate; cookies don't apply. Registered outside the WithSession/CSRF middleware groups.
- **`/userinfo` bearer-only.** WWW-Authenticate challenge shape differentiates missing (no `error=`) from invalid_token from insufficient_scope per RFC 6750 §3. Also returns JSON body for clients that don't read the challenge header.
- **`return_to` open-redirect defense.** `validateReturnTo` accepts same-origin URLs OR relative paths with a leading slash. Cross-origin → drop to `/`. Reused by /login and /consent.

### CSRF

- **gorilla/csrf over rolled-own.** HMAC token in cookie + matching form field; constant-time compare. Don't bikeshed CSRF.
- **Plaintext-HTTP gotcha discovered in testing:** gorilla/csrf v1.7.3 enforces a strict TLS-oriented Referer check that rejects every POST in dev. When `secure=false` we wrap each request with `csrf.PlaintextHTTPRequest` so the check correctly skips. Documented at `internal/http/csrf.go`.

### Dev loop

- **Full HTTP surface verified via `scripts/dev_flow.sh`** — curl-driven through all 8 steps with cookie persistence, CSRF token extraction from HTML, HTML entity decoding on hidden-field values, PKCE challenge/verifier round-trip.
- **`make dev-all`** is the one-shot bootstrap: fresh KEK+CSRF keys in `/tmp/idp-env`, DB state truncated, localdev client seeded, signing key generated + activated, smoke-alice user created.

## Open questions (subproject-local)

- **KEK rewrap CLI** — stretch. `idp keys rewrap` takes an OLD_KEK + NEW_KEK env and re-encrypts all stored private keys. Trivial but noise for a lab.
- **Access-log sampling** — per-request JSON log is fine for dev; at real scale we'd sample. Deferred indefinitely.
- **`oidc-client-ts` browser test** — we've driven the flow via curl but never validated against a real OIDC client library. Worth doing before calling the subproject done.
- **Form-post response mode** for /authorize — RFC 6749 default is query; form_post keeps the code out of URLs. Deferred.
- **Refresh token reuse detection (Level 3)** — schema supports it (`rotated_from` chain). Stretch.

## Commands & Snippets

```bash
# ----- one-shot dev bootstrap -----
make dev-all            # secrets + reset + signing key + test user
make dev-serve          # run IdP in foreground
make oauth-url          # print pastable /authorize URL (browser flow)
make dev-flow           # drive full auth-code flow via curl

# ----- individual dev targets -----
make dev-secrets        # (re)generate /tmp/idp-env (FORCE=1 to regenerate)
make dev-reset          # TRUNCATE state, re-seed localdev client
make dev-key            # idempotent: generate + activate signing key
make dev-user           # idempotent: create smoke-alice@example.com

# ----- compose + lifecycle -----
make up-idp-only        # just postgres-idp
make up                 # postgres-idp + postgres-fga + openfga
make migrate            # IdP schema (ClickHouse? no — that's url-shortener)
make up-app / make down-app / make restart-app / make status-app
make up-all / make down-all

# ----- CLI subcommands -----
idp users create <email> <password>
idp users list
idp keys generate
idp keys list
idp keys activate <kid>
idp keys retire <kid>

# ----- debug -----
# Peek at pending outbox events (layer 8):
docker compose exec postgres-idp psql -U idp -d idp -c \
    "SELECT id, event_type, created_at, processed_at FROM fga_outbox ORDER BY id DESC LIMIT 10;"

# OpenFGA playground (layer 8+):
open http://localhost:3000
```

## Env vars

### cmd/idp serve

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | `postgres://idp:idp@localhost:5434/idp?sslmode=disable` | Host port 5434 (avoids url-shortener's 5432) |
| `HTTP_ADDR` | `:8080` | |
| `ISSUER_URL` | `http://localhost:8080` | Baked into every token as `iss` |
| `JWT_SIGNING_KEY_ENCRYPTION_KEY` | — | **Required.** 64 hex chars (32 bytes). Wraps private signing keys at rest via AES-256-GCM. |
| `CSRF_KEY` | — | **Required.** 64 hex chars. Signs CSRF tokens on /login + /consent forms. |
| `ACCESS_TOKEN_TTL` | `15m` | |
| `ID_TOKEN_TTL` | `5m` | |
| `REFRESH_TOKEN_TTL` | `720h` (30d) | |
| `LOG_LEVEL` | `info` | `debug \| info \| warn \| error` |
| `SHUTDOWN_GRACE` | `15s` | |

### cmd/idp keys / users

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | — | Required |
| `JWT_SIGNING_KEY_ENCRYPTION_KEY` | — | Required for `keys` subcommands |

### cmd/outbox-worker (planned, layer 8)

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | same as idp | |
| `OPENFGA_API_URL` | `http://localhost:8081` | |
| `OPENFGA_STORE_ID` | — | Required |
| `BATCH_SIZE` | `100` | |
| `BLOCK_DURATION` | `1s` | |

### cmd/docs-api (layer 9)

| Var | Default | Notes |
|-----|---------|-------|
| `HTTP_ADDR` | `:8083` | `:8082` is OpenFGA's gRPC port on the host |
| `TRUSTED_ISSUERS` | — | Comma-separated allowlist; multi-issuer learning |
| `REQUIRED_AUD` | `docs-api` | |
| `OPENFGA_API_URL` | `http://localhost:8081` | |
| `OPENFGA_STORE_ID` | same as worker | |
| `OPENFGA_AUTHORIZATION_MODEL_ID` | same as worker | |
| `ALLOWED_ORIGINS` | (empty) | Comma-separated CORS origins; e.g. `http://localhost:5173` for Vite dev |
| `SHUTDOWN_GRACE` | `15s` | |
| `LOG_LEVEL` | `info` | debug\|info\|warn\|error |

### web/ (stretch — Vite + React SPA)

- Mono-frontend: `/` = docs product, `/admin` = IdP admin (scope-gated).
- Stack: Vite + React 18 + TypeScript + Tailwind + React Router + TanStack Query + `react-oidc-context` + react-hook-form.
- **Token storage**: in-memory only. Reload triggers silent re-auth via the IdP session cookie + refresh token flow. No `localStorage` / `sessionStorage` for tokens (XSS exposure).
- **Dev proxy** in `vite.config.ts` rewrites `/api/docs` → `:8083/` and `/api/admin` → `:8080/admin/api/` so the SPA calls same-origin and we dodge CORS in dev.
- **Prod / non-proxied dev**: docs-api + IdP admin API honor `ALLOWED_ORIGINS` via `go-chi/cors`.

## References

- **In-repo:**
  - README.md — full design doc
  - docs/architecture.md — component deep-dive + Mermaid sequence diagrams
  - docs/rfcs.md — spec index + reading order
  - docs/learning_objectives.md — the 4 learning gaps mapped to code
  - docs/tradeoffs.md — smaller decisions during build
- **External:**
  - [OpenFGA docs](https://openfga.dev/docs/getting-started)
  - [Auth0 FGA docs](https://docs.fga.dev/) (matt's day-job context)
  - [oidc-client-ts](https://github.com/authts/oidc-client-ts)
  - [golang-jwt](https://github.com/golang-jwt/jwt)
  - [gorilla/csrf](https://github.com/gorilla/csrf)
  - [go-webauthn](https://github.com/go-webauthn/webauthn) (layer 10 stretch)
