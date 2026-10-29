-- A user's provider links become first-class records. The users table holds exactly one
-- oauth_provider / oauth_id pair, so signing in with a second provider overwrites the
-- first — the original link is destroyed with no record and no warning.
--
-- Identity here is (provider, provider_account_id): the provider's own stable identifier.
-- That is what stops a merely-asserted email address from being sufficient to reach an
-- account. Uniqueness is on the pair rather than on provider alone, so one user may link
-- two accounts at the same provider (a personal and a work Google account, say).
--
-- This is the expand half of an expand/contract pair: the legacy columns stay, and the
-- callback keeps them in step, so this migration is revertible on its own.

CREATE TABLE IF NOT EXISTS "accounts" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(255) NOT NULL,
  provider_account_id VARCHAR(255) NOT NULL,
  email CITEXT,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT accounts_provider_account_unique UNIQUE (provider, provider_account_id)
);

CREATE TRIGGER accounts_set_updated_at
  BEFORE UPDATE ON accounts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS "accounts_user_id" ON "accounts" (user_id);

-- Backfill one row per existing link so current users keep signing in without re-linking.
-- The empty-string test is not redundant: the library writes '' rather than NULL for an
-- unset provider.
INSERT INTO accounts (user_id, provider, provider_account_id, email)
SELECT id, oauth_provider, oauth_id, email
FROM users
WHERE oauth_provider IS NOT NULL AND oauth_provider <> ''
  AND oauth_id IS NOT NULL AND oauth_id <> ''
ON CONFLICT (provider, provider_account_id) DO NOTHING;
