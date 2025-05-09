-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Create temporary table without sensitive fields
CREATE TABLE oauth2_config_new (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id INTEGER NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    modified_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Copy data from old table to new table
INSERT INTO oauth2_config_new (id, user_id, redirect_uri, enabled, modified_date)
SELECT id, user_id, redirect_uri, enabled, modified_date
FROM oauth2_config;

-- Drop old table
DROP TABLE oauth2_config;

-- Rename new table to original name
RENAME TABLE oauth2_config_new TO oauth2_config;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

-- Create temporary table with all fields
CREATE TABLE oauth2_config_old (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id INTEGER NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    modified_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Copy data from current table to old table, with placeholder values for sensitive fields
INSERT INTO oauth2_config_old (id, user_id, client_id, client_secret, tenant_id, redirect_uri, enabled, modified_date)
SELECT id, user_id, 'from_env', 'from_env', 'from_env', redirect_uri, enabled, modified_date
FROM oauth2_config;

-- Drop current table
DROP TABLE oauth2_config;

-- Rename old table to original name
RENAME TABLE oauth2_config_old TO oauth2_config; 