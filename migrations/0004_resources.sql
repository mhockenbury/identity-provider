-- 0004_resources.sql — RFC 8707 resource indicators
--
-- Audience semantics: `aud` identifies the *resource server* that should
-- accept the token, not the OAuth *client* that requested it. Previously
-- the IdP issued aud=<client_id>, conflating the two (documented as a
-- lab shortcut in docs/tradeoffs.md). This migration unwinds it.
--
-- Per-client `resources` allowlist: which resource servers the client
-- may request tokens for. /authorize requires `resource=` and validates
-- it against this list.
--
-- Per-grant `resource`: stored on auth_codes + refresh_tokens so /token
-- can mint access tokens with the correct `aud`. Refresh-rotated tokens
-- inherit the parent's resource.

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS resources TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';

-- Backfill the dev-seeded clients so the existing flow still works.
-- These match scripts/seed_client.sql; idempotent.
UPDATE clients SET resources = ARRAY['docs-api']
    WHERE id = 'localdev-docs' AND resources = '{}';

UPDATE clients SET resources = ARRAY['docs-api', 'idp-admin']
    WHERE id = 'localdev-admin' AND resources = '{}';

UPDATE clients SET resources = ARRAY['docs-api', 'idp-admin']
    WHERE id = 'localdev' AND resources = '{}';
