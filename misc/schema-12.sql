BEGIN TRANSACTION;

DELETE FROM log_entry WHERE idx >= 0;
ALTER TABLE log_entry DROP COLUMN leaf_input;

ALTER TABLE log_entry ADD COLUMN cert_md5 bytea;
UPDATE log_entry SET cert_md5 = '';
ALTER TABLE log_entry ALTER COLUMN cert_md5 SET NOT NULL;

COMMIT;
