-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE IF EXISTS oauth2_tokens;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
CREATE TABLE IF NOT EXISTS oauth2_tokens (
    id TEXT PRIMARY KEY,
    app_registration_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    access_token BLOB NOT NULL,
    refresh_token BLOB,
    token_type TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_registration_id) REFERENCES app_registrations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
); 