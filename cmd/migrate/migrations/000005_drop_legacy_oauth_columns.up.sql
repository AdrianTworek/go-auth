-- The contract half of the accounts migration. Provider links now live in the accounts
-- table, which has been the source of truth since 000004; these columns have only been
-- kept in step so that migration stayed revertible on its own.
--
-- They cannot represent what the library now supports: a user may hold several links,
-- and two columns can hold one. Keeping them would mean keeping a second, lossy answer
-- to "which providers can sign this person in?".

ALTER TABLE "users" DROP COLUMN IF EXISTS "oauth_provider";
ALTER TABLE "users" DROP COLUMN IF EXISTS "oauth_id";
