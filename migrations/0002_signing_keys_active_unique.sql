-- 0002_signing_keys_active_unique.sql
--
-- Enforce "at most one active signing key" as a DB constraint.
-- Defense in depth: application code also checks, but the DB is the
-- final word — two concurrent Activate calls can't both succeed.
--
-- An "active" key is activated_at IS NOT NULL AND retired_at IS NULL.
-- Postgres supports partial unique indexes on boolean expressions, which
-- is exactly what we need. A trivial constant column (1) keyed by the
-- predicate guarantees at most one row matches the predicate.

CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_active_idx
    ON signing_keys ((1))
    WHERE activated_at IS NOT NULL
      AND retired_at IS NULL;
