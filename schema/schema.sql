BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 1;

CREATE TABLE files (
    file_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content_length TEXT NOT NULL,
    finished BOOLEAN NOT NULL DEFAULT FALSE
);

END TRANSACTION;
