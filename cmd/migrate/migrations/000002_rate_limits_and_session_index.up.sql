-- Index session lookups by user_id. ListForUser / DeleteForUser /
-- DeleteOthersForUser / DeleteByIDForUser all filter on user_id and were
-- sequential scans without this.
CREATE INDEX IF NOT EXISTS "sessions_user_id" ON "sessions" (user_id);

-- Backing table for the optional Postgres rate-limit store (token bucket). One row
-- per rate-limit key; "tokens" is the current bucket level and "updated_at" is when
-- it was last refilled/consumed. Rows for idle keys are pruned by DeleteStale.
CREATE TABLE IF NOT EXISTS "rate_limits" (
  key VARCHAR(255) PRIMARY KEY,
  tokens DOUBLE PRECISION NOT NULL,
  updated_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW()
);
