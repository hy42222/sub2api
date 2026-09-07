-- Key/IP audit dispositions. The audit aggregates remain derived from usage_logs;
-- these tables only store administrator decisions and trusted network rules.
CREATE TABLE IF NOT EXISTS key_ip_audit_trusted_ips (
    id          BIGSERIAL PRIMARY KEY,
    api_key_id  BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    cidr        VARCHAR(64) NOT NULL,
    note        VARCHAR(500) NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ,
    created_by  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT key_ip_audit_trusted_ips_key_cidr_unique UNIQUE (api_key_id, cidr)
);

CREATE INDEX IF NOT EXISTS idx_key_ip_audit_trusted_ips_key_expires
    ON key_ip_audit_trusted_ips (api_key_id, expires_at);

CREATE TABLE IF NOT EXISTS key_ip_audit_dismissals (
    id           BIGSERIAL PRIMARY KEY,
    api_key_id   BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    ip_address   VARCHAR(45) NOT NULL,
    risk_code    VARCHAR(64) NOT NULL,
    event_start  TIMESTAMPTZ NOT NULL,
    event_end    TIMESTAMPTZ NOT NULL,
    note         VARCHAR(500) NOT NULL DEFAULT '',
    created_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT key_ip_audit_dismissals_event_range CHECK (event_start < event_end)
);

CREATE INDEX IF NOT EXISTS idx_key_ip_audit_dismissals_key_ip_time
    ON key_ip_audit_dismissals (api_key_id, ip_address, event_start, event_end);

-- PostgreSQL 14 does not provide pg_input_is_valid (introduced in PostgreSQL 16).
-- The repository SQL calls this function directly and expects an inet return
-- value. Invalid collector input is deliberately converted to NULL. CIDR
-- notation and interface zones are not client IPs and must not be accepted.
CREATE OR REPLACE FUNCTION try_inet(raw_ip TEXT)
RETURNS INET
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    cleaned TEXT;
    parsed INET;
    mapped_value BIGINT;
BEGIN
    cleaned := BTRIM(raw_ip);
    IF cleaned = '' OR POSITION('/' IN cleaned) > 0 OR POSITION('%' IN cleaned) > 0 THEN
        RETURN NULL;
    END IF;

    BEGIN
        parsed := cleaned::INET;
    EXCEPTION WHEN invalid_text_representation THEN
        RETURN NULL;
    END;

    -- inet_subnet_of handles both dotted-decimal and hexadecimal spellings
    -- of IPv4-mapped IPv6 addresses. Convert the low 32 bits arithmetically
    -- instead of parsing HOST(), whose presentation is version-dependent.
    IF FAMILY(parsed) = 6 AND parsed <<= '::ffff:0:0/96'::INET THEN
        mapped_value := parsed - '::ffff:0:0'::INET;
        IF mapped_value < 0 OR mapped_value > 4294967295 THEN
            RETURN NULL;
        END IF;
        RETURN '0.0.0.0'::INET + mapped_value;
    END IF;

    RETURN parsed;
END;
$$;
