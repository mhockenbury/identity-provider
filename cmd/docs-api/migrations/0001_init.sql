-- +goose Up
-- 0001_init.sql — docs-api schema (folders + documents).
--
-- Owned by the docs service. Separate Postgres from postgres-idp;
-- coordinated only via the access token's `sub` claim (which we store
-- as owner_sub on documents) and FGA tuples (which live in OpenFGA's
-- own DB and reference the same UUIDs we store here).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE folders (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id   UUID REFERENCES folders(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX folders_parent_id_idx ON folders(parent_id);

CREATE TABLE documents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Optional: a doc can live at the top level (no folder).
    folder_id   UUID REFERENCES folders(id) ON DELETE SET NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL DEFAULT '',
    -- The IdP user (sub claim) who owns this row in *application* terms.
    -- Authorization is FGA-driven; this column is for display + audit.
    owner_sub   TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX documents_folder_id_idx ON documents(folder_id);
CREATE INDEX documents_owner_sub_idx ON documents(owner_sub);

-- +goose Down
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS folders;
