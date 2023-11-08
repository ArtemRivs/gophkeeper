CREATE TABLE IF NOT EXISTS client
(
    id            uuid default gen_random_uuid() PRIMARY KEY,
    "login"       varchar(100) NOT NULL,
    password_hash varchar(100) NOT NULL,
    CONSTRAINT unique_login UNIQUE (login)
);
CREATE TABLE IF NOT EXISTS login_password
(
    id         uuid default gen_random_uuid() PRIMARY KEY,
    user_id    uuid          NOT NULL,
    "key"      varchar(100)  NOT NULL,
    "login"    varchar(100)  NOT NULL,
    "password" varchar(100)  NOT NULL,
    meta       varchar(1000) NOT NULL,
    deleted    bool default false,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES client (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_password_user_key ON login_password (user_id, "key") WHERE deleted is FALSE;
CREATE TABLE IF NOT EXISTS card
(
    id         uuid default gen_random_uuid() PRIMARY KEY,
    user_id    uuid          NOT NULL,
    "key"      varchar(100)  NOT NULL,
    number     varchar(100)  NOT NULL,
    expiration varchar(100)  NOT NULL,
    "name"     varchar(100)  NOT NULL,
    surname    varchar(100)  NOT NULL,
    cvv        varchar(100)  NOT NULL,
    meta       varchar(1000) NOT NULL,
    deleted    bool default false,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES client (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_card_user_key ON card (user_id, "key") WHERE deleted is FALSE;
CREATE TABLE IF NOT EXISTS text
(
    id      uuid default gen_random_uuid() PRIMARY KEY,
    user_id uuid         NOT NULL,
    "key"   varchar(100) NOT NULL,
    "path" varchar(100) NOT NULL,
    meta       varchar(1000) NOT NULL,
    deleted    bool default false,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES client (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_text_user_key ON card (user_id, "key") WHERE deleted is FALSE;
