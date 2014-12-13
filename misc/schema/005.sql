ALTER TABLE log_entry ADD COLUMN domain text not null default 'UNKNOWN';
DELETE FROM log_entry WHERE idx > 0;
