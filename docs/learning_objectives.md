# Learning Objectives — identity-provider

The "capacity estimates" section of the standard subproject template is
replaced here with this file. I2 is a protocol-and-correctness learning
project; numbers would be noise.

Each objective is either **covered by core** (guaranteed by the implementation
plan) or **covered by stretch** (only if the subproject extends past core).

## Primary objectives

### OIDC authorization code flow with PKCE from the inside
Understand *why* each flow parameter exists, not just what the spec says.
Expect to be able to explain: why `state`, why PKCE even for confidential
clients, what `nonce` protects, why ID tokens are signed but opaque to APIs.

**Covered by:** core. `internal/oauth/authorize.go`, `internal/oauth/token.go`.
**Verified by:** oidc-client-ts browser smoke test completing a full flow.

### JWT + JWKS key management
Signing, `kid` lookup, public key distribution, key rotation mechanics,
client-side JWKS caching with refresh-on-unknown-kid.

**Covered by:** core. `internal/tokens/*`, `/.well-known/jwks.json`, demo-api
JWKS cache.
**Verified by:** demo-api validates tokens across a simulated key rotation
(IdP rotates signing key; demo-api refetches JWKS on cache miss for new kid).

### Refresh token rotation (Level 2)
Each refresh invalidates the old refresh token and issues a new one.
Requires a DB schema that tracks rotation state.

**Covered by:** core. `internal/tokens/refresh.go`, `refresh_tokens` table
with `rotated_from` self-ref.
**Verified by:** test that reusing a rotated refresh token returns
`invalid_grant`.

### Outbox pattern for eventual consistency
Transactional identity state + pending outbox row, async worker drains
to downstream (FGA). The realistic pattern for "do one thing atomically,
propagate eventually."

**Covered by:** core. `internal/outbox/*`, `cmd/outbox-worker/main.go`.
**Verified by:** add a user to a group via the IdP, observe the FGA tuple
appear within O(1s) without either system blocking the other.

## Named learning gaps (matt's weak areas)

### Issuer validation with multiple possible issuers
Most tutorials show single-issuer validation and skip the hard part.
In real systems you may accept tokens from your own IdP *and* an upstream
or sibling IdP. This forces: per-issuer JWKS cache, `iss` allowlist, handling
`kid` collisions between issuers.

**Covered by:** core. demo-api configured with two trusted issuers (our IdP
+ a mock second one, e.g., a simple second IdP instance with its own keys).
**Verified by:** demo-api accepts tokens from either issuer, rejects tokens
with valid signatures from the wrong issuer (e.g., mock issuer's token used
against an endpoint that only trusts our IdP — and vice versa).

### Downstream signature verification
demo-api validates tokens entirely locally — it never calls the IdP per-
request. This is how production services work and is where JWT + JWKS
earn their complexity budget. Covers: signature, `exp`, `iss`, `aud`,
scope presence.

**Covered by:** core. `cmd/demo-api`'s token-validating middleware.
**Verified by:**
- Forged-token test case (sign with a local random key, assert rejection)
- JWKS-cache-miss test case (IdP rotates, demo-api's cache has only the old
  `kid`; the new `kid` triggers a refetch; subsequent tokens work)
- Expired-token test case (exp in the past, assert rejection)

### Scope-based authz (vs FGA authz)
The subtle distinction most engineers miss: *scope* is what the user+client
has been *allowed to ask for* (set at consent time, encoded in the token).
*Authz* is what this specific access can actually do (FGA check at request
time). Both are needed; they're not redundant.

**Covered by:** core. `cmd/demo-api` enforces scope in middleware
(fast-fail) and FGA check in handler (fine-grained).
**Verified by:**
- Request with `read:docs` scope but no viewer tuple on the specific doc
  → 403 (scope present, FGA denies)
- Request without `read:docs` scope → 403 (scope missing, FGA never called)
- Design doc paragraph in README §6 explicitly contrasting the two

### Token binding (DPoP)
Stretch. The goal isn't a full RFC 9449 implementation; it's to feel why
sender-constraining tokens exists. Bearer tokens can be stolen and replayed;
DPoP binds the token to a client-held key so a stolen token is useless
without the key.

**Covered by:** stretch. One endpoint on demo-api that requires a DPoP
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

### Token exchange (RFC 8693)
Stretch. Adds `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
to `/token`. Lets a service downscope an incoming token for a further
downstream call (`aud` change, scope subset).

**Verified by:** demo-api exchanges its incoming token for a scope-reduced
one before calling a hypothetical second downstream service.

### Dynamic client registration (RFC 7591)
Likely skipped. Admin UI would fit better first.

---

## What I expect to feel at the end

By the time core is done, matt should be able to:

- Walk through an OIDC flow from scratch without looking at a diagram
- Explain what the `kid` in a JWT header is doing
- Explain what `aud` is for and what happens if you ignore it
- Describe the scope-vs-authz distinction in a sentence
- Know where to look in the spec for "does this refresh token work across clients" (it doesn't)
- Have internalized the outbox pattern well enough to apply it to unrelated projects
- Read a token at `jwt.io` and tell you what's wrong with it
- Design a JWKS rotation plan for a service consuming tokens from multiple IdPs

Stretch goals expand this but are not required for the subproject to be "done."
