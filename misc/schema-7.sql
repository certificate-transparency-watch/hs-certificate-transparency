-- Query to optimise:
--   select max(idx) from log_entry where log_server_id = 1;
CREATE INDEX ON log_entry(log_server_id, idx);

-- Query to optimise:
--   select * from log_entry where domain like '%.google.com';
-- i.e. a suffix query
--
-- Postgres cannot (?) index strings with suffix tree, but can with a prefix tree
-- so indexing on the reverse means we get the performance gains we want, though we must query like:
--   select * from log_entry where reverse(domain) like 'moc.elgoog.%';
CREATE INDEX ON log_entry(reverse(domain) text_pattern_ops);
