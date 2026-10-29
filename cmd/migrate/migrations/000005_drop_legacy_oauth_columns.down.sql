ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "oauth_provider" VARCHAR(255);
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "oauth_id" VARCHAR(255);

-- Best-effort restore: a user with several links had only one representable here, so
-- the oldest is chosen for determinism.
UPDATE users u
SET oauth_provider = a.provider,
    oauth_id = a.provider_account_id
FROM (
  SELECT DISTINCT ON (user_id) user_id, provider, provider_account_id
  FROM accounts
  ORDER BY user_id, created_at ASC
) a
WHERE a.user_id = u.id;
