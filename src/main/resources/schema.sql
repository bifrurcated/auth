CREATE TABLE IF NOT EXISTS usr
(
    id         BIGSERIAL PRIMARY KEY,
    first_name VARCHAR(255) NOT NULL,
    last_name  VARCHAR(255) NOT NULL,
    email      VARCHAR(255) NOT NULL,
    password   VARCHAR(255) NOT NULL
);

ALTER TABLE usr
    DROP CONSTRAINT IF EXISTS unique_email;
ALTER TABLE IF EXISTS usr
    ADD CONSTRAINT unique_email UNIQUE (email);

CREATE TABLE IF NOT EXISTS token
(
    id            BIGSERIAL PRIMARY KEY,
    refresh_token VARCHAR(255) NOT NULL,
    issue_at      TIMESTAMP    NOT NULL,
    expired_at    TIMESTAMP    NOT NULL,
    "user"        BIGINT       NOT NULL,

    CONSTRAINT fk_token_user FOREIGN KEY ("user") REFERENCES usr (id)
);

CREATE TABLE IF NOT EXISTS password_recovery
(
    id     BIGSERIAL PRIMARY KEY,
    token  VARCHAR(255) NOT NULL,
    "user" BIGINT       NOT NULL,

    CONSTRAINT fk_password_recovery_user FOREIGN KEY ("user") REFERENCES usr (id)
);

ALTER TABLE IF EXISTS usr
ADD COLUMN IF NOT EXISTS tfa_secret VARCHAR(255) default '';