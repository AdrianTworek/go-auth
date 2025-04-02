DROP TABLE IF EXISTS tokens;

CREATE TYPE "verification_intent" AS ENUM ('password_reset', 'email_verification', 'one_time_password', 'magic_link');

-- replace the old tokens table with the new more versatile verifications table that can 
-- handle user specific verification intents as well as generic ones
CREATE TABLE IF NOT EXISTS "verifications" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  value VARCHAR(255) NOT NULL,
  intent verification_intent NOT NULL,
  user_id UUID NULL REFERENCES users(id),
  expires_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "verification_user_id" ON "verifications" (user_id);
CREATE INDEX IF NOT EXISTS "verification_value" ON "verifications" (value);
