CREATE TABLE IF NOT EXISTS "tokens" (
  user_id UUID NOT NULL REFERENCES users(id),
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),

  PRIMARY KEY (user_id, token)
);

CREATE INDEX IF NOT EXISTS "tokens_user_id" ON "tokens" (user_id);
CREATE INDEX IF NOT EXISTS "tokens_expires_at" ON "tokens" (expires_at);
