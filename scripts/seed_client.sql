-- Seed local test clients for the oidc-client-ts smoke tests + the SPA.
-- Run with: docker compose exec -T postgres-idp psql -U idp -d idp < scripts/seed_client.sql
--
-- Three clients live here, all public (PKCE-only, no secret):
--
--   localdev        — kept for back-compat with curl-driven smoke scripts
--                     (scripts/dev_flow.sh, scripts/docs_smoke.sh). Has the
--                     full scope superset so those scripts can request any
--                     mix without re-seeding.
--   localdev-docs   — used by the SPA on /, /docs/* routes. Excludes admin.
--   localdev-admin  — used by the SPA on /admin/* routes. Includes admin.
--
-- The two-client split mirrors how real IdPs separate product clients
-- from admin tools — different audiences, different consent prompts,
-- different blast radius if one is compromised. See docs/tradeoffs.md.

INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants, allowed_scopes, resources, is_public)
VALUES (
    'localdev',
    NULL,
    ARRAY['http://localhost:5173/callback', 'http://localhost:5173/', 'http://localhost:8080/debug/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['openid', 'profile', 'email', 'read:docs', 'write:docs', 'admin'],
    ARRAY['docs-api', 'idp-admin'],
    TRUE
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants, allowed_scopes, resources, is_public)
VALUES (
    'localdev-docs',
    NULL,
    ARRAY['http://localhost:5173/callback', 'http://localhost:5173/'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['openid', 'profile', 'email', 'read:docs', 'write:docs'],
    ARRAY['docs-api'],
    TRUE
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants, allowed_scopes, resources, is_public)
VALUES (
    'localdev-admin',
    NULL,
    ARRAY['http://localhost:5173/admin/callback', 'http://localhost:5173/'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['openid', 'profile', 'email', 'read:docs', 'write:docs', 'admin'],
    ARRAY['docs-api', 'idp-admin'],
    TRUE
)
ON CONFLICT (id) DO NOTHING;
