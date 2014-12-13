INSERT INTO log_server (id, prefix, name) VALUES (3, 'ct.izenpe.com', 'ct.izenpe.com');
INSERT INTO log_server (id, prefix, name) VALUES (4, 'ct1.digicert-ct.com/log', 'ct1.digicert-ct.com/log');
INSERT INTO log_server (id, prefix, name) VALUES (5, 'ct.googleapis.com/rocketeer', 'ct.googleapis.com/rocketeer');

INSERT INTO log_entry (log_server_id, idx, domain, cert_md5, log_entry_type) VALUES (3, -1, 'UNKNOWN', '\x', 0);
INSERT INTO log_entry (log_server_id, idx, domain, cert_md5, log_entry_type) VALUES (4, -1, 'UNKNOWN', '\x', 0);
INSERT INTO log_entry (log_server_id, idx, domain, cert_md5, log_entry_type) VALUES (5, -1, 'UNKNOWN', '\x', 0);
