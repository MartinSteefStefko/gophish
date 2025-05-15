-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
DROP TABLE IF EXISTS oauth2_tokens;
CREATE TABLE oauth2_tokens (
    id TEXT PRIMARY KEY,
    app_registration_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    token_encrypted TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_registration_id) REFERENCES app_registrations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_oauth2_tokens_app_registration_id ON oauth2_tokens(app_registration_id);
CREATE INDEX idx_oauth2_tokens_user_id ON oauth2_tokens(user_id);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE IF EXISTS oauth2_tokens; 