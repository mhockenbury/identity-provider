# identity-provider — Notes

Subproject-local notes: decisions during implementation, commands, references.
The README is the design doc; this file is the working log.

## Decisions made during scaffolding

- **Go module path:** `github.com/mhockenbury/identity-provider`
- **OpenFGA version:** pinned to `openfga/openfga:v1.9.4` (current stable at scaffold time). Upgrade explicitly when there's a reason.
- **Storage backend for OpenFGA:** Postgres (mirrors realistic deployment). Separate DB from IdP.
- **Go version target:** 1.25 (matches url-shortener; go.mod will tick up automatically when a dep requires it, same as before)
- **Binaries live on host during dev**, compose runs only the databases + OpenFGA (same pattern as url-shortener)
- **Signing alg:** deferred to implementation (leaning Ed25519 / `EdDSA`)
- **Session storage:** Postgres (`sessions` table in migration), not Redis — keeps the compose minimal
- **Scope for seed:** one public OAuth client `localdev` seeded via `scripts/seed_client.sql` with PKCE-only authentication

## Open questions (subproject-local)

- **Argon2id parameters** — OWASP 2024 defaults are memory=64MB, iterations=3, parallelism=4. Hardcode for now; revisit if login becomes too slow on dev machines
- **How to generate the first signing key** — options: CLI subcommand (`idp keys generate`), startup hook if no active key exists, Makefile target. Leaning CLI subcommand so it's explicit
- **KEK env var shape** — single 32-byte AES-GCM key vs a keyring? Single key is enough for lab; keyring would be overkill
- **Should we support `form_post` response mode** for /authorize? RFC 6749 default is `query`; `form_post` is more secure (not in URL). Defer to later.
- **oidc-client-ts** smoke test: vanilla Playwright or just a hand-clicked browser flow? Start with hand-clicked until basics work

## Commands & Snippets

```bash
# Bring up everything (compose deps + build + start)
make up-all

# Just the Postgres + OpenFGA containers
make up
make migrate                   # IdP schema
docker compose exec -T postgres-idp psql -U idp -d idp < scripts/seed_client.sql

# Run the three binaries in the background (after implementation)
make up-app                    # idp :8080, outbox-worker, demo-api :8081
make status-app
make logs-idp
make down-app

# OpenFGA playground UI (once server is running)
open http://localhost:3000

# Peek at pending outbox events
docker compose exec postgres-idp psql -U idp -d idp -c \
    "SELECT id, event_type, created_at, processed_at FROM fga_outbox ORDER BY id DESC LIMIT 10;"

# Peek at FGA tuples via OpenFGA HTTP API (after stores are created)
curl -s http://localhost:8081/stores | jq
```

## Env vars (planned)

### cmd/idp
| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | `postgres://idp:idp@localhost:5434/idp?sslmode=disable` | host port 5434 (5432 reserved for url-shortener) |
| `HTTP_ADDR` | `:8080` | |
| `ISSUER_URL` | `http://localhost:8080` | |
| `JWT_SIGNING_KEY_ENCRYPTION_KEY` | — | required; 32 bytes hex-encoded, wraps private signing keys at rest |
| `ACCESS_TOKEN_TTL` | `15m` | |
| `ID_TOKEN_TTL` | `5m` | |
| `REFRESH_TOKEN_TTL` | `720h` | 30 days |
| `AUTH_CODE_TTL` | `60s` | |
| `LOG_LEVEL` | `info` | |
| `SHUTDOWN_GRACE` | `15s` | |

### cmd/outbox-worker
| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | same as idp | |
| `OPENFGA_API_URL` | `http://localhost:8081` | |
| `OPENFGA_STORE_ID` | — | required, from `openfga CreateStore` output |
| `BATCH_SIZE` | `100` | |
| `BLOCK_DURATION` | `1s` | sleep when no rows |
| `SHUTDOWN_GRACE` | `10s` | |

### cmd/demo-api
| Var | Default | Notes |
|-----|---------|-------|
| `HTTP_ADDR` | `:8082` | |
| `TRUSTED_ISSUERS` | — | comma-separated; for multi-issuer learning |
| `REQUIRED_AUD` | `demo-api` | |
| `OPENFGA_API_URL` | `http://localhost:8081` | |
| `OPENFGA_STORE_ID` | same as worker | |
| `LOG_LEVEL` | `info` | |

## References

- README.md — full design doc
- docs/architecture.md — component deep-dive
- docs/rfcs.md — spec index with one-line summaries + "what we implement"
- docs/learning_objectives.md — the learning targets, mapped to code
- docs/tradeoffs.md — smaller decisions during build
- OpenFGA docs: https://openfga.dev/docs/getting-started
- Auth0 FGA docs: https://docs.fga.dev/ (matt's day-job context)
- oidc-client-ts: https://github.com/authts/oidc-client-ts
- go-webauthn: https://github.com/go-webauthn/webauthn
- golang-jwt: https://github.com/golang-jwt/jwt
