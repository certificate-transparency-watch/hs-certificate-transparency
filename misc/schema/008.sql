TRUNCATE TABLE log_entry;
ALTER TABLE log_entry DROP COLUMN leaf_input;
ALTER TABLE log_entry ADD COLUMN leaf_input bytea not null;

ALTER TABLE log_entry DROP COLUMN extra_data;
ALTER TABLE log_entry ADD COLUMN extra_data bytea not null;
