-- +goose Up
-- SQL in this section is executed when the migration is applied.
DELETE FROM oauth_tokens WHERE id IN (
    SELECT id FROM (
        SELECT id,
        ROW_NUMBER() OVER (PARTITION BY user_id, provider_tenant_id ORDER BY created_at DESC) as rn
        FROM oauth_tokens
    ) t
    WHERE t.rn > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_provider ON oauth_tokens (user_id, provider_tenant_id);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
DROP INDEX IF EXISTS idx_user_provider; 