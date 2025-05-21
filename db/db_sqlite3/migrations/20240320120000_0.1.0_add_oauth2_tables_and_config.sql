-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Create OAuth2 tables
CREATE TABLE oauth2_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    modified_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE oauth2_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_type TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    modified_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert initial OAuth2 config for admin user
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
    '${TEST_CLIENT_ID}',
    '${TEST_CLIENT_SECRET}',
    '${OAUTH2_PROVIDER_TENANT_ID}',
    'https://localhost:3333/oauth2/callback',
    1,
    CURRENT_TIMESTAMP
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DELETE FROM oauth2_config WHERE user_id = 1;
DROP TABLE oauth2_tokens;
DROP TABLE oauth2_config; 