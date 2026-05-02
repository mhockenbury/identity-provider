# Tradeoffs — identity-provider

Core tradeoffs live in the README §6. This doc captures smaller decisions
made during implementation + items explicitly flagged for later review.

## Resolved in README §6

- **JWT access tokens, no introspection**
- **Outbox pattern for FGA sync**
- **Refresh token rotation (Level 2) with 30s reuse grace, no family-graph yet**
- **Separate Postgres databases for IdP and OpenFGA**
- **Server-rendered HTML for login + consent, SPA for product surfaces** (docs UI + admin UI both live in `web/`)

## Resolved during implementation

### Signing algorithm: Ed25519
Chose `EdDSA` (Ed25519). 32-byte keys, fast deterministic signing, minimal
JWKS payload. We support one alg only — no RS256 fallback. Switching to RS256
later would be a config change + schema column (alg already exists but CHECK
currently allows both; we only produce EdDSA).

### Session storage: Postgres
Stuck with Postgres (`sessions` table). Keeps compose minimal; writes aren't
a hot path at our scale. Revisit if we ever want cross-IdP-instance session
replication without Postgres as the serialization point.

### Session cookie is unsigned
Carries session ID only; server validates by DB lookup. Forged ID fails
lookup → equivalent security for our purposes. A real IdP would HMAC-sign
(defense in depth + allows in-cookie data without DB hit). Flagged in
`internal/users/sessions.go` package comment.

### JWT lifetimes
- Access token: 15 min (`ACCESS_TOKEN_TTL`)
- ID token: 5 min (`ID_TOKEN_TTL`)
- Refresh token: 30 days (`REFRESH_TOKEN_TTL`)
- Auth code: 60 seconds (hard-coded `DefaultCodeTTL`)

All env-configurable except the auth-code TTL. RFC 6749 recommends ≤60s
for codes; no strong reason to make it tunable.

### Consent granularity: per-(user, client), scope set UPSERT
Single row per pair. Scope-set match is subset-aware: consented to
`[a,b,c]` → requesting `[a]` passes, requesting `[a,d]` re-prompts.
Alternative "prompt once per scope globally" rejected — loses client
context, lets a dangerous scope bleed across clients.

### Secret/KEK storage: env var
`JWT_SIGNING_KEY_ENCRYPTION_KEY` = 32 bytes hex-encoded. AES-256-GCM wraps
the signing-key private halves. `kid` bound as AAD so a row-mix bug fails
the AEAD check loud. Deliberately simple — a real IdP would use cloud KMS
or HashiCorp Vault. The `KEK` interface is tiny so swapping is trivial
when we care.

### Client secrets: argon2id (not encryption)
Same hash primitive as user passwords. We never need the plaintext post-
registration. Eliminates a second hash stack.

### Password hashing: argon2id with PHC encoding
Default params: memory=64MB, iterations=3, parallelism=4 (OWASP 2024).
Params are encoded inside each hash (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`),
so future bumps don't invalidate existing hashes — verification reads
params from the hash, not from current defaults.

### Signing-key rotation: 3-state timestamps + partial unique index
`activated_at` + `retired_at` derive state (PENDING/ACTIVE/RETIRED).
Partial unique index `signing_keys_one_active_idx` enforces "at most one
active" at the DB level — a race or code bug can't produce two actives.
Admin-driven rotation via `idp keys {generate,activate,retire}` CLI; no
automation. Retired keys stay in the table (and in JWKS output until
explicitly pruned) so in-flight tokens verify during the overlap window.

### KeyResolver split: internal vs downstream
Two implementations of `tokens.KeyResolver`:
- `KeyStoreResolver` (internal): hits Postgres directly. Used by
  `/userinfo` and the IdP's admin API so the IdP verifies its own tokens
  with no HTTP round-trip through its own JWKS endpoint.
- `internal/jwks.Cache` (downstream): HTTP-fetched JWKS with per-issuer
  caching, refresh-on-unknown-kid, TTL + stale-if-error. Used by
  `cmd/docs-api`. Real "downstream signature verification" lesson lives
  here.

### CSRF: gorilla/csrf + plaintext-HTTP workaround
Library choice: gorilla/csrf. We don't roll our own token scheme.

Gotcha found in testing: gorilla/csrf v1.7.3 enforces a strict TLS-oriented
Referer check that rejects every POST when the deployment is plaintext HTTP
(the check defends against HTTP MITM injecting forms into nominally-TLS
sites — false positive when we KNOW we're plaintext). The library exposes
`csrf.PlaintextHTTPRequest` for exactly this; our `CSRFMiddleware` applies
it when `secure=false`.

### Auth codes: plaintext in DB
60s TTL + single-use. Hashing adds no meaningful security (brute force is
irrelevant at that TTL, and an attacker with DB read already has everything
interesting). Refresh tokens DO hash — 30-day window makes "DB dump hands
attacker active bearer credentials" a real concern.

### Auth code single-use: UPDATE ... WHERE used_at IS NULL RETURNING
Atomic claim pattern; concurrent Consume calls serialize via
row-locking. 8-goroutine race test (`TestCodes_ConsumeIsAtomic`): exactly
1 succeeds, 7 get `ErrCodeAlreadyUsed`.

Related: **client mismatch check happens BEFORE the claim**, so a
wrong-client request does NOT burn the code. The legitimate holder can
still redeem.

### Refresh token rotation: SELECT FOR UPDATE in a transaction
Stronger serialization than the UPDATE-RETURNING trick — we need to
read the row (scopes for downgrade check) AND atomically revoke + issue
new. A `BEGIN tx + SELECT FOR UPDATE + INSERT new + UPDATE old revoked
+ COMMIT` sequence means concurrent Rotate calls with the same token
race cleanly; only one wins.

### OAuth error response: error= group semantics
Per RFC 6749 §5.2, many failure modes map to the same error code:
- `invalid_grant` covers: code not found, code expired, code already used,
  code client/redirect_uri mismatch, refresh token not found, refresh
  expired, refresh revoked, refresh client mismatch
- This is deliberate: distinguishing would leak state to attackers.

Similarly at `/userinfo`:
- Unknown user (deleted after token issuance) → `invalid_token`, not a
  distinct "user not found" — treat as "token no longer valid."

### Refresh-token reuse grace window (30s)
When the same refresh-token plaintext is presented twice within 30s of a
successful rotation, the second call returns the cached response instead
of `invalid_grant`. Solves the canonical browser-SPA race (StrictMode
double-mount, tab refocus, network retry). In-memory cache, hashed keys,
TTL-bounded. Implementation: `internal/oauth/refresh_grace.go`. Allowed
by the OAuth 2.1 BCP draft when the window is short and bounded.

### Admin scope gating: dual-layer (consent-time filter + runtime is_admin check)
The `admin` scope is gated twice for defense-in-depth:
1. **Consent-time filter**: the consent handler silently drops `admin`
   from the granted scope set when `users.is_admin = false`. The user
   gets a token without `admin` rather than an error page.
2. **Runtime check** in admin API middleware: even if the token has
   `admin` scope, every admin call re-checks `users.GetByID(claims.Sub).IsAdmin`.
   Catches the case where someone is demoted between consent and request.

Either gate alone would work; both gates together let demotion take
effect immediately (no waiting for token expiry).

### Admin API redirect URI reuse
Lab shortcut: the `/logout` handler validates `post_logout_redirect_uri`
against the client's `redirect_uris` allowlist instead of a separate
`post_logout_redirect_uris` field. Production OIDC IdPs maintain the two
allowlists separately. Documented at `internal/http/logout.go`.

### Resource indicators (RFC 8707) + two-client SPA model
The IdP issues access tokens with `aud=<resource-server-identity>`, not
`aud=<client_id>`. `/authorize` requires the `resource=` query param;
the value must be in the client's registered `resources` allowlist.
`/token` reads the resource off the auth_code or refresh_token row and
sets `aud` accordingly. ID tokens still use `aud=<client_id>` per OIDC
Core (the ID token is *for* the client; the access token is *for* the
resource server).

The SPA splits across two OAuth clients to match this model:
- `localdev-docs` (resource=docs-api, scopes openid+email+read:docs+write:docs)
  — used on the docs route tree (`/`, `/docs/*`).
- `localdev-admin` (resource=idp-admin, scopes openid+email+admin) —
  used on the admin route tree (`/admin/*`).

Each route tree mounts its own `<AuthProvider>` with namespaced
sessionStorage prefixes (`oidc.docs:` / `oidc.admin:`) so PKCE
verifiers + state + nonce don't collide during interleaved logins.
Different `redirect_uri` per provider (`/callback` vs `/admin/callback`)
disambiguates which provider completes the post-/authorize redirect.

The third resource server in the IdP process — `/userinfo` — is a
deliberate exception. Per OIDC Core, the userinfo endpoint validates
iss + signature + scope=openid; it does NOT enforce a specific `aud`
because it's served by the issuer itself. Auth0, Okta, and Google all
behave the same way. So we run two verifiers in the IdP: a strict
`adminVerifier` (audience=`idp-admin`) for `/admin/api/*` and a
permissive `userInfoVerifier` (audience=any) for `/userinfo`.

This replaces an earlier lab shortcut where the IdP issued
`aud=<client_id>` and the resource server matched on that. The shortcut
collapsed two distinct identities (client and resource) into one and
made multi-client deployments structurally awkward.

## Pending / to be decided later

### Outbox worker `LISTEN/NOTIFY`
Currently 1s polling. `LISTEN/NOTIFY` on the outbox table would let the
worker wake immediately on new rows. Polling is fine at lab scale.

### Refresh token reuse detection (Level 3, family-graph)
Schema supports it via `rotated_from`. Promote when we want to simulate
the stolen-token scenario — reused refresh token *outside* the grace
window invalidates the whole rotation chain. The 30s grace window
co-exists cleanly with this: same-token reuse within window → cache hit
(intended); same-token reuse outside window → invalidate chain
(stolen-token signal).

### Introspection endpoint (RFC 7662)
Add if we ever need revocation latency < access-token expiry. JWT + 15m
expiry is acceptable for the lab; introspection changes the architecture
materially (every protected request becomes a round-trip back to the IdP).

### mTLS client authentication (RFC 8705)
Confidential clients could authenticate via client-cert instead of
client_secret. Public clients already use PKCE-only, which is fine.

### DPoP / sender-constrained tokens (RFC 9449)
Demonstrate on one docs-api endpoint post-layer 9. Full RFC 9449
implementation is out of scope; the goal is "feel why it exists."

### Dynamic client registration (RFC 7591)
Skipped; admin UI would come first. Current flow: seed via SQL or CLI.

### Consent revocation
Users cannot revoke consent themselves — no UI, no API. Consent stays
until overwritten by a new Grant or the client is deleted.

### Auto-rotate signing keys on schedule
Manual-only for now via `idp keys` CLI. A small scheduler goroutine
inside `serve` would handle this, but operator-driven rotation is closer
to real IdP patterns anyway.

### KEK rewrap CLI
`idp keys rewrap` would take an `OLD_KEK` + `NEW_KEK` env pair and
re-encrypt all stored private keys under the new KEK. Trivial to write;
noise for a lab.

### form_post response mode for /authorize
RFC 6749 default is query-string; OpenID's `response_mode=form_post`
keeps the code out of URLs (better for referer + history). Defer.

### Rate limiting on /userinfo, /token
A leaked access token is usable for its full TTL; real IdPs rate-limit
per-sub on /userinfo and per-client on /token. Out of scope for the
lab; flag for production-hardening checklist.
