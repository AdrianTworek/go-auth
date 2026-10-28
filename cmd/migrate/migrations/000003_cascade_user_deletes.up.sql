-- Deleting a user currently fails outright: the foreign keys from sessions and
-- verifications to users were declared inline with no ON DELETE clause, so Postgres
-- refuses the delete with a constraint violation. Nothing in the library deletes a user
-- yet, which is why this has gone unnoticed.
--
-- Make the dependency explicit at the database rather than unpicking it in application
-- code: the foreign-key graph then lives in one place, and a table added later cannot be
-- forgotten in the way that produces orphans.

ALTER TABLE "sessions" DROP CONSTRAINT IF EXISTS "sessions_user_id_fkey";
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey"
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE "verifications" DROP CONSTRAINT IF EXISTS "verifications_user_id_fkey";
ALTER TABLE "verifications" ADD CONSTRAINT "verifications_user_id_fkey"
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
