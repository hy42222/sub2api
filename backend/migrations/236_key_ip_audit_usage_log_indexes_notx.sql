-- usage_logs is a large, frequently written table. Build the expression index
-- outside a transaction so startup does not hold a table-wide write lock.
-- The expression must match the repository SQL exactly.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_usage_logs_key_ip_audit_ip_created
    ON usage_logs (
        api_key_id,
        (host(try_inet(NULLIF(BTRIM(ip_address), '')))),
        created_at DESC,
        id DESC
    )
    WHERE ip_address IS NOT NULL AND ip_address <> '';
