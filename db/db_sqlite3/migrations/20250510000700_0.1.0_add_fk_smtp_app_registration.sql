-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
PRAGMA foreign_keys=OFF;

CREATE TABLE smtp_new (
    id integer primary key autoincrement,
    user_id bigint,
    interface_type varchar(255),
    name varchar(255),
    host varchar(255),
    username varchar(255),
    password varchar(255),
    from_address varchar(255),
    modified_date datetime default CURRENT_TIMESTAMP,
    ignore_cert_errors BOOLEAN,
    app_registration_id VARCHAR(255),
    FOREIGN KEY (app_registration_id) REFERENCES app_registrations(id)
);

INSERT INTO smtp_new SELECT * FROM smtp;
DROP TABLE smtp;
ALTER TABLE smtp_new RENAME TO smtp;

PRAGMA foreign_keys=ON;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

PRAGMA foreign_keys=OFF;

CREATE TABLE smtp_old (
    id integer primary key autoincrement,
    user_id bigint,
    interface_type varchar(255),
    name varchar(255),
    host varchar(255),
    username varchar(255),
    password varchar(255),
    from_address varchar(255),
    modified_date datetime default CURRENT_TIMESTAMP,
    ignore_cert_errors BOOLEAN,
    app_registration_id VARCHAR(255)
);

INSERT INTO smtp_old SELECT * FROM smtp;
DROP TABLE smtp;
ALTER TABLE smtp_old RENAME TO smtp;

PRAGMA foreign_keys=ON;