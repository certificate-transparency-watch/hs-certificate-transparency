create index on log_entry ((domain IS NULL), log_server_id);
drop index log_entry_domain_idx;
drop index log_entry_log_server_id_expr_idx;
