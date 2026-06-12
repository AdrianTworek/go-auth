-- Truncate any over-long values so the narrower type can be restored.
ALTER TABLE sessions ALTER COLUMN user_agent TYPE VARCHAR(255) USING LEFT(user_agent, 255);
