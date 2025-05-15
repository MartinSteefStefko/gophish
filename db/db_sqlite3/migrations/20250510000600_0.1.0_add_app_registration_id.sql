-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE smtp ADD COLUMN app_registration_id VARCHAR(255);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
ALTER TABLE smtp DROP COLUMN app_registration_id; 