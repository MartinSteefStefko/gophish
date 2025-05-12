-- +goose Up
-- SQL in this section is executed when the migration is applied.

-- Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create provider_tenants table
CREATE TABLE IF NOT EXISTS provider_tenants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    provider_tenant_id TEXT NOT NULL,
    display_name TEXT,
    region TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create app_registrations table
CREATE TABLE IF NOT EXISTS app_registrations (
    id TEXT PRIMARY KEY,
    provider_tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_hash TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    redirect_uri TEXT,
    scopes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (provider_tenant_id) REFERENCES provider_tenants(id) ON DELETE CASCADE
);

-- Create features table
CREATE TABLE IF NOT EXISTS features (
    id TEXT PRIMARY KEY,
    app_registration_id TEXT NOT NULL,
    feature_type TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (app_registration_id) REFERENCES app_registrations(id) ON DELETE CASCADE
);

-- Create oauth_tokens table
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_provider_tenant_id ON oauth_tokens(provider_tenant_id);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.

DROP TABLE IF EXISTS oauth_tokens;
DROP TABLE IF EXISTS features;
DROP TABLE IF EXISTS app_registrations;
DROP TABLE IF EXISTS provider_tenants;
DROP TABLE IF EXISTS tenants; 