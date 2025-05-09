-- +goose Up
-- SQL in this section is executed when the migration is applied.
CREATE TABLE oauth2_config (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id INTEGER,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    modified_date DATETIME NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE oauth2_tokens (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id INTEGER NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    token_type VARCHAR(50) NOT NULL,
    expires_at DATETIME NOT NULL,
    modified_date DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
DROP TABLE oauth2_tokens;
DROP TABLE oauth2_config; 