# Learning Objectives — identity-provider

The "capacity estimates" section of the standard subproject template is
replaced here with this file. I2 is a protocol-and-correctness learning
project; numbers would be noise.

Each objective is either **covered by core** (guaranteed by the implementation
plan) or **covered by stretch** (only if the subproject extends past core).

**Status as of subproject 2 close-out:** all primary objectives ✓ landed.
3 of 4 named gaps ✓ (DPoP carries forward). Stretch UIs ✓ (docs SPA + admin UI),
refresh-grace ✓. WebAuthn / DPoP / token-exchange / family-graph reuse-detection
deferred to follow-on subprojects.

## Primary objectives

### OIDC authorization code flow with PKCE from the inside
Understand *why* each flow parameter exists, not just what the spec says.
Expect to be able to explain: why `state`, why PKCE even for confidential
clients, what `nonce` protects, why ID tokens are signed but opaque to APIs.

**Covered by:** core. `internal/oauth/authorize.go`, `internal/oauth/token.go`, `internal/http/login.go`, `internal/http/consent.go`. **Status: ✓**
**Verified by:** `scripts/dev_flow.sh` (curl-driven) + the `web/` SPA's `Sign in` button (browser-driven, oidc-client-ts).

### JWT + JWKS key management
Signing, `kid` lookup, public key distribution, key rotation mechanics,
client-side JWKS caching with refresh-on-unknown-kid.

**Covered by:** core. `internal/tokens/keys.go` (3-state PENDING/ACTIVE/RETIRED with partial unique index), `internal/tokens/jwks.go` (wire format), `internal/tokens/jwt.go` (signer + verifier with kid lookup), `internal/jwks/cache.go` (HTTP-fetched cache with refresh-on-unknown-kid). **Status: ✓**
**Verified by:** `internal/jwks/cache_test.go::TestResolve_UnknownKid_TriggersRefetch` (rotation path), `TestIntegration_VerifierAcceptsFetchedKey` (full integration with a real EdDSA JWT).

### Refresh token rotation (Level 2)
Each refresh invalidates the old refresh token and issues a new one.
Requires a DB schema that tracks rotation state.

**Covered by:** core. `internal/tokens/refresh.go` (Rotate uses BEGIN tx + SELECT FOR UPDATE), schema in migration 0001 with `rotated_from` self-ref. **Status: ✓**
**Plus:** 30-second reuse grace window (`internal/oauth/refresh_grace.go`) to handle the canonical browser-SPA race where parallel calls present the same token.
**Verified by:** 8-goroutine concurrent rotate test in `refresh_test.go` proves exactly one wins; live race test of 2 parallel + 1 sequential `/token` POSTs all returning byte-identical 200 responses.

### Outbox pattern for eventual consistency
Transactional identity state + pending outbox row, async worker drains
to downstream (FGA). The realistic pattern for "do one thing atomically,
propagate eventually."

**Covered by:** core. `internal/outbox/{events,store,translate}.go` (`Enqueue(ctx, tx, event)` insists on a `pgx.Tx` so atomicity is compile-time-enforced), `cmd/outbox-worker/main.go` (claim batch via `SELECT FOR UPDATE SKIP LOCKED`, per-tuple coalescing across batch, attempt_count cap with poison-pill quarantine). **Status: ✓**
**Verified by:** `scripts/docs_smoke.sh` end-to-end + `internal/outbox/*_test.go` unit tests; also exercised live via the admin UI's group-membership-CRUD which writes an outbox row, drained within ~1s.

## Named learning gaps (my weak areas)

### Issuer validation with multiple possible issuers
Most tutorials show single-issuer validation and skip the hard part.
In real systems you may accept tokens from your own IdP *and* an upstream
or sibling IdP. This forces: per-issuer JWKS cache, `iss` allowlist, handling
`kid` collisions between issuers.

**Covered by:** core. The `tokens.Verifier` takes `map[string]KeyResolver` as the issuer allowlist; `cmd/docs-api/main.go` builds one `jwks.Cache` per `TRUSTED_ISSUERS` entry. **Status: ✓** (mechanism in place; second-issuer integration test would be a 1-line config change to spin up a second IdP).
**Verified by:** `cmd/docs-api/auth_test.go::TestAuthenticate_UnknownIssuer_401` (token from a legitimate-but-untrusted issuer is rejected before key resolution); `internal/jwks/cache_test.go::TestIntegration_VerifierAcceptsFetchedKey` (real cross-process JWKS fetch + token validation).

### Downstream signature verification
docs-api validates tokens entirely locally — it never calls the IdP per-
request. This is how production services work and is where JWT + JWKS
earn their complexity budget. Covers: signature, `exp`, `iss`, `aud`,
scope presence.

**Covered by:** core. `cmd/docs-api/auth.go` (`authenticate` middleware), `cmd/docs-api/main.go` (per-issuer `jwks.Cache` wiring). **Status: ✓**
**Verified by:**
- `cmd/docs-api/auth_test.go::TestAuthenticate_ExpiredToken_401` (expired token rejected)
- `internal/jwks/cache_test.go::TestResolve_UnknownKid_TriggersRefetch` (rotation path: cache has only old kid, new kid triggers refetch, subsequent tokens validate)
- `cmd/docs-api/auth_test.go::TestAuthenticate_HappyPath_PopulatesClaims` (signature verify succeeds, claims appear in ctx)
- `cmd/docs-api/auth_test.go::TestAuthenticate_WrongAudience_401` + `TestAuthenticate_UnknownIssuer_401` (every standard claim rejection path)

### Scope-based authz (vs FGA authz)
The subtle distinction most engineers miss: *scope* is what the user+client
has been *allowed to ask for* (set at consent time, encoded in the token).
*Authz* is what this specific access can actually do (FGA check at request
time). Both are needed; they're not redundant.

**Covered by:** core. `cmd/docs-api/auth.go::requireScope("read:docs"|"write:docs")` in middleware (fast-fail before any DB/FGA work) + `cmd/docs-api/handlers.go::resolvePermission` in handler (fine-grained tier check via FGA). Same split on the IdP's admin API: `internal/http/admin/middleware.go` requires `admin` scope, then defense-in-depth `is_admin=true` lookup. **Status: ✓**
**Verified by:**
- `cmd/docs-api/handlers_test.go::TestUpdateDoc_ReadScope_403` (correct scope is write:docs; read:docs alone returns 403 even with editor tuple)
- `cmd/docs-api/handlers_test.go::TestGetDoc_NotViewer_404` (scope present, FGA denies → 404 by design)
- `internal/http/admin/middleware_test.go::TestAuthenticate_NoAdminScope_403` + `TestAuthenticate_AdminScopeButNotIsAdmin_403` (the dual gate in action)
- README §6 "JWT access tokens" + the new "scope vs FGA" reasoning in `cmd/docs-api/handlers.go`'s package comment

### Token binding (DPoP)
Stretch. The goal isn't a full RFC 9449 implementation; it's to feel why
sender-constraining tokens exists. Bearer tokens can be stolen and replayed;
DPoP binds the token to a client-held key so a stolen token is useless
without the key.

**Covered by:** stretch. One endpoint on docs-api that requires a DPoP
header alongside the access token, with the DPoP JWT's `jkt` claim
matching the access token's `cnf.jkt` claim. Using a library; not
implementing the full spec.
**Verified by:** test showing a replay of a captured access token without
the matching DPoP proof is rejected.

## Secondary objectives (stretch goals)

### WebAuthn / passkeys as second factor
After core works. Use `github.com/go-webauthn/webauthn`. Start with
registration-after-login (2FA enrollment) + second-factor login.
Passwordless is a further stretch.

**Verified by:** manual browser test; registering a passkey + subsequent
login requires it.

### Refresh token reuse detection
Stretch. Promotes Level 2 rotation → Level 3 with family invalidation.
Schema already has `rotated_from`; add `family_id` column (or compute the
chain root via recursive CTE) and invalidate the whole chain on reuse.

**Verified by:** test: use refresh token R1, rotate to R2, then try R1
again → invalidates R2 as well; any access token issued from R2 is
implicitly "poisoned" (we don't revoke JWTs — but the user is forced to
reauthenticate since no refresh works).

### Token introspection (RFC 7662)
Stretch. Adds `POST /introspect` returning `{active, sub, aud, scope, exp, ...}`
for a presented token. The motivation is to feel why JWT-validating
resource servers *don't* need this and what changes if you switch to
opaque tokens — introspection requires the caller to authenticate, which
is the cleanest reason to register a confidential client (e.g.
`docs-api-introspector`). Sets up the broader point that resource servers
become OAuth clients the moment they make authenticated outbound calls.

**Verified by:** docs-api flips to opaque-token mode behind a flag, calls
`/introspect` with `client_secret_basic`, and rejects unknown/expired
tokens. Cache hit/miss visible in logs to show the latency tradeoff vs
local JWKS validation.

### Service-to-service via `client_credentials`
Stretch. Adds `grant_type=client_credentials` to `/token`. The use case:
a backend (e.g. an indexing job in docs-api, or outbox-worker calling a
hypothetical search-api) needs to call another service with no user in
the loop. The caller is a confidential client with no `sub` — the token's
subject *is* the client. Forces the discussion of how `aud`, scopes, and
FGA tuples differ when the principal is a service rather than a user.

**Verified by:** a small `cmd/indexer` (or outbox-worker extension) that
authenticates with `client_secret_basic`, receives a service token scoped
to a specific resource, and calls docs-api on its own behalf. Test asserts
docs-api distinguishes service-principal tokens from user tokens.

### Token exchange (RFC 8693)
Stretch. Adds `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
to `/token`. Lets a service downscope an incoming user token for a further
downstream call (`aud` change, scope subset) — the on-behalf-of pattern.
Distinct from `client_credentials` above: that one acts as the service
itself; this one acts as the user but through the service. Both require
the caller to be a confidential client.

**Verified by:** docs-api exchanges its incoming token for a scope-reduced
one before calling a hypothetical second downstream service. Test confirms
the new token's `aud` is the downstream service and its scopes are a strict
subset of the original.

### Dynamic client registration (RFC 7591)
Likely skipped. Admin UI would fit better first.

### Client application / SPA integration — ✓ DONE
The full SPA shipped at `web/`. Vite + React + TypeScript + Tailwind
+ `react-oidc-context` (over `oidc-client-ts`) + TanStack Query.
**Status: ✓**

The SPA is a mono-frontend with two route trees:
- `/` (landing) → `/docs` — docs product UI
- `/admin/*` — IdP admin UI (scope-gated)

**Surface covered:**
- PKCE from the browser (the library handles `crypto.subtle.digest`)
- In-memory token storage only — no `localStorage` / `sessionStorage`
  for the tokens themselves (XSS exposure surface)
- Silent renewal via refresh_token grant + the IdP's reuse-grace window
- Per-route scope gating (`useHasScope`); admin link hidden when token
  doesn't have `admin` scope
- Typed API clients (`web/src/docs/api.ts`, `web/src/admin/api.ts`)
- React Query for server state + cache invalidation on mutations
- RP-initiated logout (`signoutRedirect` → IdP `/logout` →
  `post_logout_redirect_uri` validated against client's allowlist)

**Verified by:** full browser round-trip — sign in, see permission
badges per doc, edit/delete based on tier, switch to admin, manage
users/groups/outbox, sign out cleanly.

---

## End-state competencies

After core, I should be able to: walk an OIDC flow from scratch without a diagram; explain `kid`, `aud`, and the scope-vs-authz distinction in one sentence each; design a JWKS rotation plan for a multi-IdP consumer; and apply the outbox pattern to an unrelated project. Stretch goals expand this but aren't required for "done."
