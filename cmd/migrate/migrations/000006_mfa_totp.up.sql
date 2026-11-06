-- Two-factor authentication with an authenticator app, plus single-use backup codes.
--
-- Two tables and one enum value. The challenge that sits between a correct password and
-- a session deliberately gets no table of its own: it rides on `verifications`, which
-- already hashes tokens at rest, consumes them atomically via DELETE ... RETURNING, and
-- sweeps its own expiries. A second mechanism alongside that would be a second thing to
-- get right.

-- A user's authenticator secret, encrypted with AES-256-GCM under a key the consumer
-- supplies. Unlike a password a TOTP secret has to be recoverable in order to verify a
-- code, so hashing is not available; encryption is what stops a leaked dump from being a
-- complete set of working second factors.
--
-- user_id is UNIQUE: one authenticator per user. That is what lets restarting enrolment
-- be an upsert, and removes any question of which of two rows is authoritative.
CREATE TABLE IF NOT EXISTS "totp_credentials" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  -- Ciphertext and the nonce it was sealed with. The nonce is not a secret; it is kept
  -- in its own column so it reads as a nonce rather than as an opaque prefix somebody
  -- later has to rediscover.
  secret BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  -- NULL until the user proves the app is set up correctly by submitting one generated
  -- code. Sign-in consults only confirmed rows, which is what stops a mis-scanned QR
  -- code from locking a user out of their own account.
  confirmed_at TIMESTAMP(0) WITH TIME ZONE,
  -- The most recent accepted time step. A code is valid for its whole window (plus the
  -- configured skew either side), so without this a code observed in transit could be
  -- replayed within its remaining validity. One column, not a table.
  last_used_step BIGINT,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER totp_credentials_set_updated_at
  BEFORE UPDATE ON totp_credentials
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Single-use recovery codes, hashed with SHA-256 rather than bcrypt. These are
-- library-generated with 50 bits of entropy, so the slow-hash reasoning that applies to
-- user-chosen passwords does not apply: there is no dictionary to run. It matches what
-- the library already does for session and verification tokens.
--
-- Because the hash is unsalted and deterministic, consuming a code is an indexed
-- equality lookup rather than a comparison against every unused code for that user.
CREATE TABLE IF NOT EXISTS "totp_backup_codes" (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Hex SHA-256 of the normalised code, so always 64 characters.
  code_hash VARCHAR(64) NOT NULL,
  used_at TIMESTAMP(0) WITH TIME ZONE,
  created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER totp_backup_codes_set_updated_at
  BEFORE UPDATE ON totp_backup_codes
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX IF NOT EXISTS "totp_backup_codes_user_id" ON "totp_backup_codes" (user_id);

-- Serves the consumption lookup and, incidentally, rules out a duplicate inside a
-- generated set.
CREATE UNIQUE INDEX IF NOT EXISTS "totp_backup_codes_user_code"
  ON "totp_backup_codes" (user_id, code_hash);

-- The challenge intent. verifications.intent is an enum, not a free string, so the new
-- value has to be added to the type.
--
-- golang-migrate wraps each migration in a transaction, and a value added to an enum
-- cannot be *used* in the transaction that adds it (and before PostgreSQL 12 could not
-- be added inside one at all). This is safe only because nothing here inserts a
-- two_factor_challenge row — do not add a backfill that does.
ALTER TYPE "verification_intent" ADD VALUE IF NOT EXISTS 'two_factor_challenge';
