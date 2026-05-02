-- +goose Up
-- 0002_seed.sql — deterministic demo corpus.
--
-- IDs match cmd/docs-api/seed_ids.go; if you change one, update both.
-- Idempotent (ON CONFLICT DO NOTHING) so re-running goose against an
-- already-seeded DB is safe.
--
-- The owner_sub here is a placeholder ("seed") — per-user authorization
-- is FGA-driven. SeedFGA writes the alice/bob/carol tuples at
-- docs-api startup using the runtime DOCS_SEED_* env vars.

INSERT INTO folders (id, parent_id, name) VALUES
    ('11111111-1111-1111-1111-000000000001'::uuid, NULL,
        'Engineering'),
    ('11111111-1111-1111-1111-000000000002'::uuid, '11111111-1111-1111-1111-000000000001'::uuid,
        'Runbooks'),
    ('11111111-1111-1111-1111-000000000003'::uuid, NULL,
        'Public')
ON CONFLICT (id) DO NOTHING;

INSERT INTO documents (id, folder_id, title, body, owner_sub) VALUES
    ('22222222-2222-2222-2222-000000000001'::uuid,
     '11111111-1111-1111-1111-000000000001'::uuid,
     'Engineering Overview',
     'What we work on, how we ship.',
     'seed'),
    ('22222222-2222-2222-2222-000000000002'::uuid,
     '11111111-1111-1111-1111-000000000002'::uuid,
     'Deploy Runbook',
     'Step-by-step production deploy procedure.',
     'seed'),
    ('22222222-2222-2222-2222-000000000003'::uuid,
     '11111111-1111-1111-1111-000000000002'::uuid,
     'On-Call Runbook',
     'Paging, escalation, and runbook links.',
     'seed'),
    ('22222222-2222-2222-2222-000000000004'::uuid,
     '11111111-1111-1111-1111-000000000003'::uuid,
     'Public README',
     'Visible to anyone viewer-on-public.',
     'seed'),
    ('22222222-2222-2222-2222-000000000005'::uuid,
     NULL,
     'Private Notes',
     'Top-level doc, tightly held.',
     'seed')
ON CONFLICT (id) DO NOTHING;

-- +goose Down
DELETE FROM documents WHERE owner_sub = 'seed';
DELETE FROM folders WHERE id IN (
    '11111111-1111-1111-1111-000000000001',
    '11111111-1111-1111-1111-000000000002',
    '11111111-1111-1111-1111-000000000003'
);
