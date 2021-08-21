BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 1;

CREATE TABLE files (
    url TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content_length TEXT NOT NULL
);

END TRANSACTION;
