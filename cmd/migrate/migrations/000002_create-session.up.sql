CREATE TABLE IF NOT EXISTS "sessions" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  token VARCHAR(255) NOT NULL UNIQUE,
  expires_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,
  ip_address VARCHAR(255) NOT NULL,
  user_agent VARCHAR(255) NOT NULL,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);