-- +goose Up
-- SQL in this section is executed when the migration is applied.
CREATE TABLE app_registrations_new (
    id TEXT PRIMARY KEY,
    provider_tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    redirect_uri TEXT,
    region TEXT,
    external_id TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (provider_tenant_id) REFERENCES provider_tenants(id)
);

INSERT INTO app_registrations_new (
    id, provider_tenant_id, client_id,
    client_secret_encrypted, redirect_uri,
    region, external_id, created_at
)
SELECT 
    id, provider_tenant_id, client_id,
    client_secret_encrypted, redirect_uri,
    region, external_id, created_at
FROM app_registrations;

DROP TABLE app_registrations;
ALTER TABLE app_registrations_new RENAME TO app_registrations;

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
CREATE TABLE app_registrations_old (
    id TEXT PRIMARY KEY,
    provider_tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    redirect_uri TEXT,
    region TEXT,
    external_id TEXT,
    use_case TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (provider_tenant_id) REFERENCES provider_tenants(id)
);

INSERT INTO app_registrations_old (
    id, provider_tenant_id, client_id,
    client_secret_encrypted, redirect_uri,
    region, external_id, use_case, created_at
)
SELECT 
    id, provider_tenant_id, client_id,
    client_secret_encrypted, redirect_uri,
    region, external_id, NULL, created_at
FROM app_registrations;

DROP TABLE app_registrations;
ALTER TABLE app_registrations_old RENAME TO app_registrations; 