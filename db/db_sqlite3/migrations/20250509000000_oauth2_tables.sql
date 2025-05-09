-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE oauth2_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    modified_date TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE oauth2_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    access_token TEXT NOT NULL,
    token_type TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMP NOT NULL,
    modified_date TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE oauth2_tokens;
DROP TABLE oauth2_config; 