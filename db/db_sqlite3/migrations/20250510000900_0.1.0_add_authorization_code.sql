-- +goose Up
-- SQL in this section is executed when the migration is applied.
ALTER TABLE oauth_tokens ADD COLUMN authorization_code TEXT;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE oauth_tokens DROP COLUMN authorization_code; 