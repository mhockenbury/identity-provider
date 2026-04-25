-- 0003: add is_admin flag to users.
--
-- Used by the consent flow to gate the `admin` scope: only users with
-- is_admin=true can grant the `admin` scope to a client. Used by the
-- admin API middleware to do a defense-in-depth check on top of the
-- scope claim.
--
-- Defaults to false so existing rows + future inserts are non-admin
-- by default — promotion is explicit (`idp users promote <email>`).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
