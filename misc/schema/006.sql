ALTER TABLE log_entry ADD CONSTRAINT log_entry_log_server_id_fk FOREIGN KEY (log_server_id) REFERENCES log_server (id);
