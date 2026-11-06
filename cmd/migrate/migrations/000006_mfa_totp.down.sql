DROP TABLE IF EXISTS "totp_backup_codes";
DROP TABLE IF EXISTS "totp_credentials";

-- The 'two_factor_challenge' enum value is deliberately left in place. PostgreSQL has no
-- ALTER TYPE ... DROP VALUE, and the workaround — recreate the type and rewrite every
-- column that uses it — is far more dangerous than leaving an unused label behind. Rows
-- carrying it are short-lived challenges that expire on their own, and the sweep in
-- CleanupExpired removes them.
