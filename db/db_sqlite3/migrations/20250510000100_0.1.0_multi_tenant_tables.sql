-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Create multi-tenant tables
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY, -- UUID as string
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS provider_tenants (
    id TEXT PRIMARY KEY, -- UUID as string
    tenant_id TEXT NOT NULL,
    provider_type TEXT NOT NULL,     -- 'azure', 'aws', etc.
    provider_tenant_id TEXT NOT NULL, -- Azure tenant GUID, AWS account ID, etc.
    display_name TEXT,
    region TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_registrations (
    id TEXT PRIMARY KEY, -- UUID as string
    provider_tenant_id TEXT NOT NULL,
    use_case TEXT NOT NULL,              -- 'phishing', 'dmarc', etc.
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL, -- encrypted, not plain
    region TEXT,
    external_id TEXT,                    -- For AWS: role ARN, etc.
    redirect_uri TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (provider_tenant_id) REFERENCES provider_tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS features (
    id TEXT PRIMARY KEY, -- UUID as string
    app_registration_id TEXT NOT NULL,
    feature_type TEXT NOT NULL,          -- 'phishing', 'dmarc', etc.
    enabled INTEGER NOT NULL DEFAULT 1,   -- SQLite boolean
    config TEXT,                         -- Store as JSON string
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_registration_id) REFERENCES app_registrations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id TEXT PRIMARY KEY, -- UUID as string
    user_id INTEGER NOT NULL,            -- Reference to Gophish user
    provider_tenant_id TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    access_token_encrypted TEXT NOT NULL,
    refresh_token_encrypted TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (provider_tenant_id) REFERENCES provider_tenants(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_provider_tenants_tenant_id ON provider_tenants(tenant_id);
CREATE INDEX IF NOT EXISTS idx_app_registrations_provider_tenant_id ON app_registrations(provider_tenant_id);
CREATE INDEX IF NOT EXISTS idx_features_app_registration_id ON features(app_registration_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_provider_tenant_id ON oauth_tokens(provider_tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id);

-- Add tenant_id columns to core tables
ALTER TABLE users ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE campaigns ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE campaigns ADD COLUMN provider_tenant_id TEXT REFERENCES provider_tenants(id) ON DELETE SET NULL;
ALTER TABLE campaigns ADD COLUMN app_registration_id TEXT REFERENCES app_registrations(id) ON DELETE SET NULL;
ALTER TABLE groups ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE templates ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE users DROP COLUMN tenant_id;
ALTER TABLE campaigns DROP COLUMN tenant_id;
ALTER TABLE campaigns DROP COLUMN provider_tenant_id;
ALTER TABLE campaigns DROP COLUMN app_registration_id;
ALTER TABLE groups DROP COLUMN tenant_id;
ALTER TABLE templates DROP COLUMN tenant_id;

DROP INDEX IF EXISTS idx_oauth_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth_tokens_provider_tenant_id;
DROP INDEX IF EXISTS idx_features_app_registration_id;
DROP INDEX IF EXISTS idx_app_registrations_provider_tenant_id;
DROP INDEX IF EXISTS idx_provider_tenants_tenant_id;

DROP TABLE IF EXISTS oauth_tokens;
DROP TABLE IF EXISTS features;
DROP TABLE IF EXISTS app_registrations;
DROP TABLE IF EXISTS provider_tenants;
DROP TABLE IF EXISTS tenants; 