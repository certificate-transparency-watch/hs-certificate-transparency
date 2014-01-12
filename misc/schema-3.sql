ALTER TABLE log_server ADD COLUMN name text;

UPDATE log_server SET name = 'google-pilot' WHERE id = 1;
UPDATE log_server SET name = 'google-aviator' WHERE id = 2;
