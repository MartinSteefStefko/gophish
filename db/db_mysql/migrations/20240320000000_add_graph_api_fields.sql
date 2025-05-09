-- +goose Up
ALTER TABLE sending_profiles
ADD COLUMN interface_type VARCHAR(10) NOT NULL DEFAULT 'SMTP',
ADD COLUMN client_id VARCHAR(255),
ADD COLUMN client_secret VARCHAR(255),
ADD COLUMN tenant_id VARCHAR(255);

-- +goose Down
ALTER TABLE sending_profiles
DROP COLUMN interface_type,
DROP COLUMN client_id,
DROP COLUMN client_secret,
DROP COLUMN tenant_id; 