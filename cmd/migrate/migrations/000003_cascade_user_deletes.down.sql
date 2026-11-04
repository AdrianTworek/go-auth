ALTER TABLE "sessions" DROP CONSTRAINT IF EXISTS "sessions_user_id_fkey";
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey"
  FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE "verifications" DROP CONSTRAINT IF EXISTS "verifications_user_id_fkey";
ALTER TABLE "verifications" ADD CONSTRAINT "verifications_user_id_fkey"
  FOREIGN KEY (user_id) REFERENCES users(id);
