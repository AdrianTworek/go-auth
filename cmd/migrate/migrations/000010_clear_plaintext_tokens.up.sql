-- Session and verification tokens are now stored as SHA-256 hashes. Existing rows
-- hold plaintext values that can no longer be matched by the hashed lookups, so
-- clear them. This forces a one-time re-login for active sessions; short-lived
-- verification tokens are simply dropped.
DELETE FROM sessions;
DELETE FROM verifications;
