ALTER TABLE log_server OWNER TO docker;
ALTER TABLE log_entry OWNER TO docker;
ALTER TABLE cert OWNER TO docker;

INSERT INTO log_entry (log_server_id, idx, domain, cert_md5, log_entry_type) VALUES (1, -1, 'UNKNOWN', '\x', 0);
INSERT INTO log_entry (log_server_id, idx, domain, cert_md5, log_entry_type) VALUES (2, -1, 'UNKNOWN', '\x', 0);
