-- Seed a local test client + demo user for the oidc-client-ts smoke test.
-- Run with: docker compose exec -T postgres-idp psql -U idp -d idp < scripts/seed_client.sql
--
-- Client secret (plaintext, never store this in real systems): "localdev-secret"
-- The argon2id hash below is regenerated at first real run; for now placeholder.

INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants, allowed_scopes, is_public)
VALUES (
    'localdev',
    NULL,  -- public client; PKCE-only
    -- The SPA uses /callback for auth-code redirects and / for
    -- post-logout redirects. Both must be registered because the
    -- logout handler validates post_logout_redirect_uri against the
    -- same redirect_uris list (lab shortcut; see docs/tradeoffs.md).
    ARRAY['http://localhost:5173/callback', 'http://localhost:5173/', 'http://localhost:8080/debug/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['openid', 'profile', 'email', 'read:docs', 'write:docs', 'admin'],
    TRUE
)
ON CONFLICT (id) DO NOTHING;
