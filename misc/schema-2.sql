CREATE TABLE log_server (
    id int UNIQUE,
    prefix text
);

INSERT INTO log_server (id, prefix) VALUES (1, 'ct.googleapis.com/pilot');

ALTER TABLE sth
    ADD COLUMN log_server_id int
    DEFAULT 1
    REFERENCES log_server(id);
