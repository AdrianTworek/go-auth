-- go-auth: the complete schema in one file, for fresh installs.
--
-- This is a snapshot of migrations/000001 through migrations/000006 applied in order. It
-- exists so a new consumer can create every table the library needs with one command —
-- `psql -f schema.sql`, or by mounting it into a Postgres container's
-- /docker-entrypoint-initdb.d/ — without adopting golang-migrate.
--
-- The incremental files in migrations/ remain the source of truth, and the only way to
-- upgrade an existing database. Never run this file against a database that already has
-- the schema.
--
-- Snapshot of: 000006_mfa_totp
--
-- To move a database created from this file onto golang-migrate later, baseline it first
-- so the migrations already reflected here are not re-run:
--
--   migrate -path cmd/migrate/migrations -database "$DSN" force 6
--
-- Test_Integration_SchemaSnapshotMatchesMigrations fails if this file and the migrations
-- disagree, so a new migration must be folded in here (and the version above bumped) in
-- the same change.

CREATE EXTENSION IF NOT EXISTS "citext";

-- Keep updated_at current on every UPDATE (DEFAULT NOW() only applies on INSERT).
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Users ---------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "users" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email CITEXT NOT NULL UNIQUE,
  password BYTEA,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  avatar_url TEXT,
  avatar_source VARCHAR(10) DEFAULT 'oauth',
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER users_set_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Sessions ------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "sessions" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  token VARCHAR(255) NOT NULL UNIQUE,
  expires_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,
  ip_address VARCHAR(255) NOT NULL,
  user_agent TEXT NOT NULL,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT "sessions_user_id_fkey"
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TRIGGER sessions_set_updated_at
  BEFORE UPDATE ON sessions
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS "sessions_user_id" ON "sessions" (user_id);

-- Verifications (emailed tokens and two-factor challenges) ------------------------------

CREATE TYPE "verification_intent" AS ENUM (
  'password_reset',
  'email_verification',
  'magic_link',
  'email_change',
  'two_factor_challenge'
);

CREATE TABLE IF NOT EXISTS "verifications" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  value VARCHAR(255) NOT NULL,
  intent verification_intent NOT NULL,
  user_id UUID NULL,
  email VARCHAR(255) NULL,
  expires_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT "verifications_user_id_fkey"
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TRIGGER verifications_set_updated_at
  BEFORE UPDATE ON verifications
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS "verification_user_id" ON "verifications" (user_id);
CREATE INDEX IF NOT EXISTS "verification_value" ON "verifications" (value);

-- Rate limits (backing table for the optional Postgres rate-limit store) ----------------

CREATE TABLE IF NOT EXISTS "rate_limits" (
  key VARCHAR(255) PRIMARY KEY,
  tokens DOUBLE PRECISION NOT NULL,
  updated_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Linked provider accounts --------------------------------------------------------------

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

-- Two-factor authentication -------------------------------------------------------------

-- secret is AES-256-GCM ciphertext under the consumer's key; nonce is the nonce it was
-- sealed with. confirmed_at stays NULL until enrolment is confirmed with a code, and
-- last_used_step blocks replay of a code within its window.
CREATE TABLE IF NOT EXISTS "totp_credentials" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  secret BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  confirmed_at TIMESTAMP(0) WITH TIME ZONE,
  last_used_step BIGINT,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER totp_credentials_set_updated_at
  BEFORE UPDATE ON totp_credentials
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Single-use recovery codes; code_hash is the hex SHA-256 of the normalised code.
CREATE TABLE IF NOT EXISTS "totp_backup_codes" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash VARCHAR(64) NOT NULL,
  used_at TIMESTAMP(0) WITH TIME ZONE,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER totp_backup_codes_set_updated_at
  BEFORE UPDATE ON totp_backup_codes
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS "totp_backup_codes_user_id" ON "totp_backup_codes" (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS "totp_backup_codes_user_code"
  ON "totp_backup_codes" (user_id, code_hash);
