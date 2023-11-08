CREATE TABLE IF NOT EXISTS "binary" (
    id uuid default gen_random_uuid() PRIMARY KEY,
    user_id uuid         NOT NULL,
    "key"   varchar(100) NOT NULL,
    "path" varchar(100) NOT NULL,
    meta       varchar(1000) NOT NULL,
    deleted    bool default false,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES client (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_binary_user_key ON "binary" (user_id, "key") WHERE deleted is FALSE;
DROP INDEX IF EXISTS unique_text_user_key;
CREATE UNIQUE INDEX IF NOT EXISTS unique_text_user_key ON text (user_id, "key") WHERE deleted is FALSE;
