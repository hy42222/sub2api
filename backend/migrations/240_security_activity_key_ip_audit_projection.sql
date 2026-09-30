-- Future-only security activity projection.
--
-- usage_logs remains the billing/source-of-truth table. This projection is a
-- bounded, minute-level read model for per-key/IP security analysis. The
-- watermark is initialized at migration time deliberately: existing history is
-- not backfilled by the Key/IP audit worker.
CREATE TABLE IF NOT EXISTS security_activity_1m (
    bucket_start             TIMESTAMPTZ NOT NULL,
    api_key_id               BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    user_id                  BIGINT NOT NULL DEFAULT 0,
    client_ip                VARCHAR(45) NOT NULL DEFAULT '',
    user_agent               VARCHAR(512) NOT NULL DEFAULT '',
    request_count            BIGINT NOT NULL DEFAULT 0,
    missing_ip_count         BIGINT NOT NULL DEFAULT 0,
    missing_user_agent_count BIGINT NOT NULL DEFAULT 0,
    first_seen                TIMESTAMPTZ NOT NULL,
    last_seen                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (bucket_start, api_key_id, user_id, client_ip, user_agent)
);

COMMENT ON TABLE security_activity_1m IS
    'Normalized future-only usage activity shared by security per-key/IP analyses.';

-- Queue rows are created in the same transaction as usage_logs. Enqueue time,
-- not usage_logs.created_at (which may use the insert transaction's old NOW()),
-- determines whether a log belongs to the future-only projection.
CREATE TABLE IF NOT EXISTS security_activity_projection_queue (
    projection_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_relation TEXT NOT NULL,
    usage_log_id BIGINT NOT NULL,
    api_key_id  BIGINT NOT NULL,
    user_id     BIGINT NOT NULL DEFAULT 0,
    ip_address  TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL,
    enqueued_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

COMMENT ON TABLE security_activity_projection_queue IS
    'Future-only usage rows waiting for normalized security projection.';

CREATE OR REPLACE FUNCTION enqueue_security_activity_projection()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.api_key_id IS NOT NULL THEN
        INSERT INTO security_activity_projection_queue
            (source_relation, usage_log_id, api_key_id, user_id, ip_address, user_agent, created_at)
        VALUES (format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME), NEW.id, NEW.api_key_id, COALESCE(NEW.user_id, 0),
                COALESCE(NEW.ip_address, ''), COALESCE(NEW.user_agent, ''), NEW.created_at);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS usage_logs_security_activity_projection ON usage_logs;
CREATE TRIGGER usage_logs_security_activity_projection
AFTER INSERT ON usage_logs
FOR EACH ROW
EXECUTE FUNCTION enqueue_security_activity_projection();

CREATE TABLE IF NOT EXISTS key_ip_audit_projection_state (
    id                       SMALLINT PRIMARY KEY CHECK (id = 1),
    live_since               TIMESTAMPTZ NOT NULL,
    processed_usage_log_id  BIGINT NOT NULL DEFAULT 0,
    processed_created_at     TIMESTAMPTZ,
    data_through             TIMESTAMPTZ,
    last_successful_at       TIMESTAMPTZ,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO key_ip_audit_projection_state (id, live_since)
-- CREATE TRIGGER takes the usage_logs table lock above. Use wall-clock time
-- after that lock is acquired so writes that were waiting for the trigger are
-- newer than the future-only boundary when they become visible.
VALUES (1, clock_timestamp())
ON CONFLICT (id) DO NOTHING;

-- The queue handles commit-order gaps; this ledger makes retries and crash
-- recovery exactly-once at the projection boundary.
CREATE TABLE IF NOT EXISTS security_activity_projection_events (
    projection_id BIGINT PRIMARY KEY,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Exact event times are needed only for clipped minute edges and partial
-- dismissals; the shared minute facts remain the ordinary read path.
CREATE TABLE IF NOT EXISTS security_activity_events (
    projection_id BIGINT PRIMARY KEY,
    source_relation TEXT NOT NULL,
    usage_log_id BIGINT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    api_key_id   BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    user_id      BIGINT NOT NULL DEFAULT 0,
    client_ip    VARCHAR(45) NOT NULL DEFAULT '',
    user_agent   VARCHAR(512) NOT NULL DEFAULT ''
);

COMMENT ON TABLE security_activity_events IS
    'Bounded future-only security events for exact time edges and dismissals.';

CREATE TABLE IF NOT EXISTS key_ip_audit_key_state (
    api_key_id   BIGINT PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    latest_ip    VARCHAR(45),
    request_count BIGINT NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS key_ip_audit_ip_state (
    api_key_id     BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    client_ip      VARCHAR(45) NOT NULL,
    first_seen     TIMESTAMPTZ NOT NULL,
    last_seen      TIMESTAMPTZ NOT NULL,
    request_count  BIGINT NOT NULL DEFAULT 0,
    user_agent_count BIGINT NOT NULL DEFAULT 0,
    user_agent     VARCHAR(512) NOT NULL DEFAULT '',
    is_baseline    BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (api_key_id, client_ip)
);

CREATE TABLE IF NOT EXISTS key_ip_audit_ip_1m (
    bucket_start     TIMESTAMPTZ NOT NULL,
    api_key_id       BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    client_ip        VARCHAR(45) NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    request_count    BIGINT NOT NULL DEFAULT 0,
    user_agent_count BIGINT NOT NULL DEFAULT 0,
    user_agent       VARCHAR(512) NOT NULL DEFAULT '',
    shared_ip        BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (bucket_start, api_key_id, client_ip)
);

CREATE TABLE IF NOT EXISTS key_ip_audit_key_1m (
    bucket_start          TIMESTAMPTZ NOT NULL,
    api_key_id            BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    first_seen            TIMESTAMPTZ NOT NULL,
    last_seen             TIMESTAMPTZ NOT NULL,
    request_count         BIGINT NOT NULL DEFAULT 0,
    missing_ip_count      BIGINT NOT NULL DEFAULT 0,
    missing_user_agent_count BIGINT NOT NULL DEFAULT 0,
    raw_rapid_ip_count    BIGINT NOT NULL DEFAULT 0,
    raw_shared_ip_count   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, api_key_id)
);

COMMENT ON TABLE key_ip_audit_key_1m IS
    'Key/IP audit minute rollup; risk flags are recomputed from security_activity_1m.';

-- Coarser normalized facts keep long audit windows bounded while preserving
-- the same reusable dimensions as security_activity_1m. Buckets are aligned
-- in UTC so their boundaries do not depend on the database session timezone.
CREATE TABLE IF NOT EXISTS security_activity_rollups (
    bucket_minutes           SMALLINT NOT NULL CHECK (bucket_minutes IN (60, 1440)),
    bucket_start             TIMESTAMPTZ NOT NULL,
    api_key_id               BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    user_id                  BIGINT NOT NULL DEFAULT 0,
    client_ip                VARCHAR(45) NOT NULL DEFAULT '',
    user_agent               VARCHAR(512) NOT NULL DEFAULT '',
    request_count            BIGINT NOT NULL DEFAULT 0,
    missing_ip_count         BIGINT NOT NULL DEFAULT 0,
    missing_user_agent_count BIGINT NOT NULL DEFAULT 0,
    first_seen               TIMESTAMPTZ NOT NULL,
    last_seen                TIMESTAMPTZ NOT NULL,
    CHECK (
        (bucket_minutes = 60 AND
         date_trunc('hour', bucket_start AT TIME ZONE 'UTC') = bucket_start AT TIME ZONE 'UTC')
        OR
        (bucket_minutes = 1440 AND
         date_trunc('day', bucket_start AT TIME ZONE 'UTC') = bucket_start AT TIME ZONE 'UTC')
    ),
    PRIMARY KEY (bucket_minutes, bucket_start, api_key_id, user_id, client_ip, user_agent)
);

COMMENT ON TABLE security_activity_rollups IS
    'Reusable UTC hour/day security activity derived incrementally from accepted projection events.';

CREATE TABLE IF NOT EXISTS key_ip_audit_key_rollups (
    bucket_minutes       SMALLINT NOT NULL CHECK (bucket_minutes IN (60, 1440)),
    bucket_start         TIMESTAMPTZ NOT NULL,
    api_key_id           BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    raw_rapid_ip_count   BIGINT NOT NULL DEFAULT 0,
    CHECK (
        (bucket_minutes = 60 AND
         date_trunc('hour', bucket_start AT TIME ZONE 'UTC') = bucket_start AT TIME ZONE 'UTC')
        OR
        (bucket_minutes = 1440 AND
         date_trunc('day', bucket_start AT TIME ZONE 'UTC') = bucket_start AT TIME ZONE 'UTC')
    ),
    PRIMARY KEY (bucket_minutes, bucket_start, api_key_id)
);

COMMENT ON TABLE key_ip_audit_key_rollups IS
    'UTC hour/day maxima for raw multi-IP burst screening; dismissal semantics remain request-time.';

CREATE INDEX IF NOT EXISTS idx_security_activity_1m_key_time
    ON security_activity_1m (api_key_id, bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_security_activity_projection_queue_created
    ON security_activity_projection_queue (created_at, projection_id);
CREATE INDEX IF NOT EXISTS idx_security_activity_1m_time_key
    ON security_activity_1m (bucket_start DESC, api_key_id);
CREATE INDEX IF NOT EXISTS idx_security_activity_1m_ip_time
    ON security_activity_1m (client_ip, bucket_start DESC)
    WHERE client_ip <> '';
CREATE INDEX IF NOT EXISTS idx_security_activity_rollups_key_resolution_time
    ON security_activity_rollups (api_key_id, bucket_minutes, bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_security_activity_projection_events_time
    ON security_activity_projection_events (projected_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_activity_events_key_time
    ON security_activity_events (api_key_id, created_at);
CREATE INDEX IF NOT EXISTS idx_security_activity_events_key_ip_time
    ON security_activity_events (api_key_id, client_ip, created_at);
CREATE INDEX IF NOT EXISTS idx_security_activity_events_ip_time_key
    ON security_activity_events (client_ip, created_at, api_key_id)
    WHERE client_ip <> '';
CREATE INDEX IF NOT EXISTS idx_security_activity_events_time_key
    ON security_activity_events (created_at, api_key_id);
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_projection_state_through
    ON key_ip_audit_projection_state (data_through);
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_ip_state_ip
    ON key_ip_audit_ip_state (client_ip, api_key_id);
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_ip_state_last_seen
    ON key_ip_audit_ip_state (last_seen)
    WHERE NOT is_baseline;
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_ip_1m_key_time
    ON key_ip_audit_ip_1m (api_key_id, bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_ip_1m_ip_time
    ON key_ip_audit_ip_1m (client_ip, bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_shared_ip_1m_time
    ON key_ip_audit_ip_1m (bucket_start DESC, api_key_id, client_ip)
    WHERE shared_ip;
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_key_1m_key_time
    ON key_ip_audit_key_1m (api_key_id, bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_key_1m_time
    ON key_ip_audit_key_1m (bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_key_ip_audit_key_rollups_key_resolution_time
    ON key_ip_audit_key_rollups (api_key_id, bucket_minutes, bucket_start DESC);
