CREATE TABLE cert (
    md5 bytea NOT NULL,
    certificate bytea NOT NULL
);

CREATE INDEX ON cert(md5);
