# RFCs — identity-provider

Index + one-line summary + where in our code each one lands. Read as needed;
this is a lookup table, not required upfront reading.

## Core (directly implemented)

### [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
The foundation. Defines the authorization code grant, refresh grant, client credentials grant, etc. We implement authorization code + refresh.

- **Read for us:** §4.1 Authorization Code Grant, §5 Access Token Response, §6 Refresh Token, §10 Security Considerations
- **Land in code:** `internal/oauth/{authorize,token}.go`

### [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636)
Proof Key for Code Exchange. Prevents authorization-code interception. Short spec — read cover-to-cover before writing the `/token` handler.

- **Read for us:** whole thing; it's short
- **Land in code:** `code_challenge` storage on auth_code, SHA-256 verify at token exchange in `internal/oauth/token.go`

### [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
OIDC is OAuth + ID tokens + `/userinfo` + discovery. Strictly an extension on top of OAuth.

- **Read for us:** §2 ID Token, §3.1 Authorization Code Flow (most relevant), §5 Standard Claims, §5.3 UserInfo Endpoint
- **Land in code:** `internal/oidc/*`, ID token issuance in `internal/tokens/*`

### [RFC 7519 — JWT](https://www.rfc-editor.org/rfc/rfc7519)
JSON Web Token structure and claims. Short and mostly schema.

- **Read for us:** §4 Registered Claim Names (iss, sub, aud, exp, iat, jti), §7 Creating and Validating a JWT
- **Land in code:** `internal/tokens/jwt.go` (using `github.com/golang-jwt/jwt/v5` — we don't roll our own)

### [RFC 7517 — JWK / JWKS](https://www.rfc-editor.org/rfc/rfc7517)
JSON Web Key format for publishing public keys.

- **Read for us:** §3 JWK representation, §5 JWK Set (JWKS)
- **Land in code:** `internal/tokens/jwks.go`, `/.well-known/jwks.json` handler

### [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
The `.well-known/openid-configuration` document. Tiny.

- **Read for us:** §4 Provider Configuration Response
- **Land in code:** `internal/oidc/discovery.go`, static config with interpolated issuer URL

### [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
How to send an access token in `Authorization: Bearer` and how servers respond with `WWW-Authenticate` errors.

- **Read for us:** §2.1 (header form), §3 (error responses)
- **Land in code:** `cmd/docs-api/*`, auth middleware

## Secondary (referenced as guard rails)

### [RFC 7009 — Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- **Status:** not implementing `/revoke`. JWT access tokens aren't revocable without introspection anyway; refresh revocation happens on rotation.

### [RFC 7662 — Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- **Status:** explicitly out of scope. Chose JWT self-validation (README §6).

### [RFC 8252 — OAuth for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- **Status:** not implementing native-app concerns (loopback redirect, claimed HTTPS scheme), but PKCE mandate here is the reason we always require PKCE, even for confidential clients.

### [RFC 6819 — OAuth 2.0 Threat Model](https://www.rfc-editor.org/rfc/rfc6819) / [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700)
- **Status:** reference when implementing anything security-sensitive. Worth skimming §4 of the BCP (the modern one) — it explains *why* PKCE, rotation, reuse detection, etc.

## Stretch (if we get there)

### [RFC 8693 — Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
Lets a service swap one token for another (downscoped, or for a different audience). Powerful and under-used.

- **Stretch trigger:** after core flows work; would add `grant_type=token_exchange` to `/token`

### [WebAuthn (W3C)](https://www.w3.org/TR/webauthn-3/) / [RFC 8949 CBOR](https://www.rfc-editor.org/rfc/rfc8949)
Passkeys. Large spec; we use `github.com/go-webauthn/webauthn`.

- **Stretch trigger:** after core works
- **Land in code (planned):** `internal/webauthn/*`, second-factor then passwordless

### [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449)
Demonstrating Proof-of-Possession. Sender-constrains tokens with a client-held key.

- **Stretch trigger:** demonstrate on one docs-api endpoint to feel why sender-constraining exists; not a full implementation

### [RFC 7523 — JWT Profile for Client Authentication](https://www.rfc-editor.org/rfc/rfc7523)
Using JWTs (instead of client_secret) for client authentication at `/token`.

- **Stretch trigger:** if we wanted to demonstrate asymmetric client auth

---

## Suggested reading order (not required)

1. **RFC 7636 (PKCE)** — cover to cover, it's short. Understand the code_verifier/code_challenge dance before you write the token handler.
2. **RFC 6749 §4.1 + §6** — just the authorization code + refresh sections. Ignore the rest of the grant types for now.
3. **RFC 7519 (JWT)** — skim §4 (claims) and §7 (validation).
4. **OIDC Core §2 (ID Token) + §3.1 (flow) + §5.3 (UserInfo)** — the OIDC delta on top of OAuth.
5. **RFC 9700 §4** — the modern security BCP. Explains why every security feature we're building exists.

Everything else is reference-as-needed.
