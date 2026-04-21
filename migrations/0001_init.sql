-- 0001_init.sql — IdP Postgres schema
-- OpenFGA manages its own schema in its own Postgres DB; not this file.

-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- for gen_random_uuid()

-- --- Users + authn ---

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Browser sessions for login + consent flow (signed cookies carry the id).
CREATE TABLE IF NOT EXISTS sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);

-- --- Groups (feeds FGA tuples via outbox) ---

CREATE TABLE IF NOT EXISTS groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS group_memberships (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, group_id)
);

-- --- OAuth clients ---

CREATE TABLE IF NOT EXISTS clients (
    id              TEXT PRIMARY KEY,
    secret_hash     TEXT,                              -- null for public (PKCE-only) clients
    redirect_uris   TEXT[] NOT NULL,
    allowed_grants  TEXT[] NOT NULL,
    allowed_scopes  TEXT[] NOT NULL,
    is_public       BOOLEAN NOT NULL DEFAULT FALSE,    -- mirrors secret_hash nullability for clarity
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- --- OAuth code/token state ---

-- Short-lived (~60s). used_at enforces single-use per RFC 6749 §4.1.2.
CREATE TABLE IF NOT EXISTS authorization_codes (
    code                    TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL REFERENCES clients(id),
    user_id                 UUID NOT NULL REFERENCES users(id),
    redirect_uri            TEXT NOT NULL,
    code_challenge          TEXT NOT NULL,             -- PKCE: SHA-256 of verifier
    code_challenge_method   TEXT NOT NULL CHECK (code_challenge_method = 'S256'),
    scopes                  TEXT[] NOT NULL,
    nonce                   TEXT,                      -- echoed into ID token
    expires_at              TIMESTAMPTZ NOT NULL,
    used_at                 TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS authorization_codes_expires_at_idx ON authorization_codes(expires_at);

-- Opaque refresh tokens (the token value lives in-band; we store a hash).
-- rotated_from supports the rotation chain; lets us add reuse detection later
-- without a migration.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      TEXT NOT NULL UNIQUE,              -- hash of opaque token value
    user_id         UUID NOT NULL REFERENCES users(id),
    client_id       TEXT NOT NULL REFERENCES clients(id),
    scopes          TEXT[] NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    rotated_from    UUID REFERENCES refresh_tokens(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_client_id_idx ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at_idx ON refresh_tokens(expires_at);

-- Tracks user-granted consent per (user, client, scope set).
-- Re-prompted on scope-set change.
CREATE TABLE IF NOT EXISTS consents (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes          TEXT[] NOT NULL,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

-- --- Signing keys ---
-- Explicit table so key rotation is observable. Private key encrypted
-- with a KEK from env var (see docs/tradeoffs.md for why this is deliberately simple).

CREATE TABLE IF NOT EXISTS signing_keys (
    kid                 TEXT PRIMARY KEY,
    alg                 TEXT NOT NULL CHECK (alg IN ('EdDSA', 'RS256')),
    public_key_jwk      BYTEA NOT NULL,
    private_key_enc     BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at        TIMESTAMPTZ,                   -- null = not yet signing
    retired_at          TIMESTAMPTZ                    -- null = still in JWKS (for verification)
);
CREATE INDEX IF NOT EXISTS signing_keys_active_idx ON signing_keys(activated_at, retired_at);

-- --- FGA outbox ---
-- Written in the same transaction as identity mutations. Worker drains
-- asynchronously, writes tuples to OpenFGA, then marks processed_at.

CREATE TABLE IF NOT EXISTS fga_outbox (
    id              BIGSERIAL PRIMARY KEY,
    event_type      TEXT NOT NULL,                     -- "user_created" | "group_membership_added" | ...
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at    TIMESTAMPTZ,
    attempt_count   INT NOT NULL DEFAULT 0,
    last_error      TEXT
);
-- Partial index over unprocessed rows so the worker's claim query stays fast
-- even when the table accumulates millions of processed rows.
CREATE INDEX IF NOT EXISTS fga_outbox_pending_idx
    ON fga_outbox(id)
    WHERE processed_at IS NULL;
