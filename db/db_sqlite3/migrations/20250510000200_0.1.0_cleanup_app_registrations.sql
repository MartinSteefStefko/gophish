-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Create the table if it doesn't exist (with the new schema)
CREATE TABLE IF NOT EXISTS app_registrations (
    id TEXT PRIMARY KEY, -- UUID as string
    provider_tenant_id TEXT NOT NULL,
    use_case TEXT NOT NULL,              -- 'oauth2', 'email', etc.
    client_id TEXT NOT NULL,
    client_secret_hash TEXT NOT NULL,     -- hashed for verification
    client_secret_encrypted TEXT NOT NULL, -- encrypted for use
    redirect_uri TEXT,
    scopes TEXT,                         -- comma-separated list of scopes
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (provider_tenant_id) REFERENCES provider_tenants(id) ON DELETE CASCADE
);

-- Create the index if it doesn't exist
CREATE INDEX IF NOT EXISTS idx_app_registrations_provider_tenant_id ON app_registrations(provider_tenant_id);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

-- Drop the table and its index
DROP INDEX IF EXISTS idx_app_registrations_provider_tenant_id;
DROP TABLE IF EXISTS app_registrations;

-- Recreate the table with the old schema
CREATE TABLE app_registrations (
    id TEXT PRIMARY KEY, -- UUID as string
    provider_tenant_id TEXT NOT NULL,
    use_case TEXT NOT NULL,              -- 'oauth2', 'email', etc.
    client_id TEXT NOT NULL,
    client_secret_hash TEXT NOT NULL,     -- hashed for verification
    client_secret_encrypted TEXT NOT NULL, -- encrypted for use
    region TEXT,
    external_id TEXT,                    -- For AWS: role ARN, etc.
    redirect_uri TEXT,
    scopes TEXT,                         -- comma-separated list of scopes
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (provider_tenant_id) REFERENCES provider_tenants(id) ON DELETE CASCADE
);

-- Recreate the index
CREATE INDEX idx_app_registrations_provider_tenant_id ON app_registrations(provider_tenant_id); 