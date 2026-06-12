-- User-Agent strings can exceed 255 characters; widen the column to TEXT so long
-- values no longer overflow and fail the session insert (which would break login).
ALTER TABLE sessions ALTER COLUMN user_agent TYPE TEXT;
