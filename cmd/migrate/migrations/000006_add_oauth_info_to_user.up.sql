ALTER TABLE users
ADD COLUMN oauth_provider VARCHAR(255);

ALTER TABLE users
ADD COLUMN oauth_id VARCHAR(255);