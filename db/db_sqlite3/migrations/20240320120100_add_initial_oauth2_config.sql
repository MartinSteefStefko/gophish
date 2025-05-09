-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

INSERT INTO oauth2_config (
    user_id,
    client_id,
    client_secret,
    tenant_id,
    redirect_uri,
    enabled,
    modified_date
) VALUES (
    1, -- admin user ID
    '${OAUTH2_CLIENT_ID}',
    '${OAUTH2_CLIENT_SECRET}',
    '${OAUTH2_TENANT_ID}',
    'https://localhost:3333/oauth2/callback',
    1,
    CURRENT_TIMESTAMP
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DELETE FROM oauth2_config WHERE user_id = 1; 