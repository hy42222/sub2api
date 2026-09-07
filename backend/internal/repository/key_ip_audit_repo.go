package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

type keyIPAuditRepository struct {
	db *sql.DB
}

const keyIPAuditReadTimeout = 30 * time.Second

func NewKeyIPAuditRepository(db *sql.DB) service.KeyIPAuditRepository {
	return &keyIPAuditRepository{db: db}
}

func isForeignKeyViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == pq.ErrorCode("23503")
}

// try_inet is supplied by the audit migration. It catches invalid collector
// values and returns NULL, which keeps unknown addresses out of risk signals.
// The migration implementation also canonicalizes IPv4-mapped IPv6 values.
// This is deliberately the only IP normalization used by audit SQL; request
// collection and gateway client-IP behavior are outside this package.
const keyIPAuditBaseCTE = `
WITH
candidate_keys AS (
	SELECT
		k.id AS key_id,
		k.name AS key_name,
		CASE WHEN k.deleted_at IS NOT NULL THEN 'deleted' ELSE LOWER(k.status) END AS key_status,
		k.user_id AS owner_user_id,
		COALESCE(u.email, '') AS user_email,
		CASE
			WHEN LENGTH(k.key) <= 8 THEN LEFT(k.key, 3) || '***'
			ELSE LEFT(k.key, 8) || '...'
		END AS key_prefix
	FROM api_keys AS k
	LEFT JOIN users AS u ON u.id = k.user_id
	WHERE ($4 = 0 OR k.id = $4)
	  AND ($5 = 0 OR k.user_id = $5)
	  AND ($6 = '' OR k.name ILIKE '%' || $6 || '%' OR k.id::text ILIKE '%' || $6 || '%')
	  AND ($7 = '' OR COALESCE(u.email, '') ILIKE '%' || $7 || '%' OR k.user_id::text ILIKE '%' || $7 || '%')
	  AND (
		$10 = '' OR
		($10 = 'inactive' AND LOWER(COALESCE(k.status, '')) <> 'active') OR
		LOWER(CASE WHEN k.deleted_at IS NOT NULL THEN 'deleted' ELSE k.status END) = $10
	  )
),
current_logs AS (
	SELECT
		ul.id,
		ul.api_key_id,
		ul.user_id,
		ul.created_at,
		host(try_inet(NULLIF(BTRIM(ul.ip_address), ''))) AS ip,
		NULLIF(BTRIM(COALESCE(ul.user_agent, '')), '') AS user_agent
	FROM usage_logs AS ul
	JOIN candidate_keys AS ck ON ck.key_id = ul.api_key_id
	WHERE ul.created_at >= $1 AND ul.created_at < $2
),
prior_logs AS (
	SELECT
		ul.id,
		ul.api_key_id,
		ul.created_at,
		host(try_inet(NULLIF(BTRIM(ul.ip_address), ''))) AS ip
	FROM usage_logs AS ul
	JOIN candidate_keys AS ck ON ck.key_id = ul.api_key_id
	WHERE ul.created_at >= $3 AND ul.created_at < $1
),
window_logs AS (
	SELECT
		ul.id,
		ul.api_key_id,
		ul.user_id,
		ul.created_at,
		host(try_inet(NULLIF(BTRIM(ul.ip_address), ''))) AS ip
	FROM usage_logs AS ul
	WHERE ul.created_at >= $1 - INTERVAL '10 minutes' AND ul.created_at < $2
),
key_window_logs AS (
	SELECT w.*
	FROM window_logs AS w
	JOIN candidate_keys AS ck ON ck.key_id = w.api_key_id
),
current_key_stats AS (
	SELECT api_key_id, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
		COUNT(*)::bigint AS request_count
	FROM current_logs
	GROUP BY api_key_id
),
prior_key_stats AS (
	SELECT api_key_id, COUNT(*)::bigint AS request_count
	FROM prior_logs
	GROUP BY api_key_id
),
volume_current_key_stats AS (
	SELECT c.api_key_id, COUNT(*)::bigint AS request_count
	FROM current_logs AS c
	WHERE NOT EXISTS (
		SELECT 1
		FROM key_ip_audit_dismissals AS d
		WHERE d.api_key_id = c.api_key_id
		  AND d.risk_code = 'volume_spike'
		  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = c.ip
		  AND d.event_start <= c.created_at AND d.event_end > c.created_at
	)
	GROUP BY c.api_key_id
),
volume_prior_key_stats AS (
	SELECT p.api_key_id, COUNT(*)::bigint AS request_count
	FROM prior_logs AS p
	WHERE NOT EXISTS (
		SELECT 1
		FROM key_ip_audit_dismissals AS d
		WHERE d.api_key_id = p.api_key_id
		  AND d.risk_code = 'volume_spike'
		  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = p.ip
		  AND d.event_start <= p.created_at AND d.event_end > p.created_at
	)
	GROUP BY p.api_key_id
),
current_ip_stats AS (
	SELECT
		api_key_id,
		ip,
		MIN(created_at) AS first_seen,
		MAX(created_at) AS last_seen,
		COUNT(*)::bigint AS request_count,
		COUNT(DISTINCT user_agent)::bigint AS user_agent_count,
		MIN(COALESCE(user_agent, '')) AS user_agent
	FROM current_logs
	WHERE ip IS NOT NULL
	GROUP BY api_key_id, ip
),
current_ip_ranked AS (
	SELECT i.*,
		ROW_NUMBER() OVER (PARTITION BY api_key_id ORDER BY first_seen, ip) AS ip_rank
	FROM current_ip_stats AS i
),
key_history AS (
	SELECT
		cks.api_key_id,
		EXISTS (
			SELECT 1
			FROM usage_logs AS h
			WHERE h.api_key_id = cks.api_key_id
			  AND h.created_at < $1
			  AND try_inet(NULLIF(BTRIM(h.ip_address), '')) IS NOT NULL
		) AS has_prior_valid_ip
	FROM current_key_stats AS cks
),
key_ip_baseline AS (
	SELECT
		i.*,
		h.has_prior_valid_ip,
		EXISTS (
			SELECT 1
			FROM usage_logs AS old_log
			WHERE old_log.api_key_id = i.api_key_id
			  AND old_log.created_at < $1
			  AND host(try_inet(NULLIF(BTRIM(old_log.ip_address), ''))) = i.ip
		) AS seen_before
	FROM current_ip_ranked AS i
	JOIN key_history AS h ON h.api_key_id = i.api_key_id
),
key_window_modes AS (
	SELECT kw.*, 'raw'::text AS mode
	FROM key_window_logs AS kw
	UNION ALL
	SELECT kw.*, 'effective'::text AS mode
	FROM key_window_logs AS kw
	WHERE NOT EXISTS (
		SELECT 1
		FROM key_ip_audit_dismissals AS d
		WHERE d.api_key_id = kw.api_key_id
		  AND d.risk_code = 'multi_ip_burst'
		  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = kw.ip
		  AND d.event_start <= kw.created_at AND d.event_end > kw.created_at
	)
),
key_ip_interval_ordered AS (
	SELECT
		api_key_id,
		ip,
		mode,
		id,
		created_at AS start_at,
		created_at + INTERVAL '10 minutes' AS end_at,
		MAX(created_at + INTERVAL '10 minutes') OVER (
			PARTITION BY api_key_id, ip, mode
			ORDER BY created_at, id
			ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
		) AS previous_end
	FROM key_window_modes
	WHERE ip IS NOT NULL
),
key_ip_interval_islands AS (
	SELECT x.*,
		SUM(CASE WHEN previous_end IS NULL OR start_at > previous_end THEN 1 ELSE 0 END) OVER (
			PARTITION BY api_key_id, ip, mode
			ORDER BY start_at, id
			ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
		) AS island_no
	FROM key_ip_interval_ordered AS x
),
key_ip_ranges AS (
	SELECT api_key_id, ip, mode, island_no, MIN(start_at) AS start_at, MAX(end_at) AS end_at
	FROM key_ip_interval_islands
	GROUP BY api_key_id, ip, mode, island_no
),
key_ip_events AS (
	SELECT api_key_id, mode, start_at AS event_at, 1::bigint AS delta FROM key_ip_ranges
	UNION ALL
	SELECT api_key_id, mode, end_at AS event_at, -1::bigint AS delta FROM key_ip_ranges
),
	key_ip_event_deltas AS (
		SELECT api_key_id, mode, event_at, SUM(delta)::bigint AS delta
		FROM key_ip_events
		GROUP BY api_key_id, mode, event_at
	),
	key_ip_sweep_events AS (
		SELECT api_key_id, mode, event_at, SUM(delta)::bigint AS delta
		FROM (
			SELECT api_key_id, mode, event_at, delta
			FROM key_ip_event_deltas
			WHERE event_at >= $1
			UNION ALL
			SELECT api_key_id, mode, $1::timestamptz AS event_at, SUM(delta)::bigint AS delta
			FROM key_ip_event_deltas
			WHERE event_at < $1
			GROUP BY api_key_id, mode
		) AS scoped_events
		GROUP BY api_key_id, mode, event_at
	),
	key_ip_sweep AS (
		SELECT api_key_id, mode, event_at,
			SUM(delta) OVER (PARTITION BY api_key_id, mode ORDER BY event_at ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)::bigint AS active_ip_count
		FROM key_ip_sweep_events
	),
	rapid_by_key AS (
		SELECT api_key_id,
			COALESCE(MAX(active_ip_count) FILTER (WHERE mode = 'raw' AND event_at < $2), 0)::bigint AS raw_rapid_ip_count,
			COALESCE(MAX(active_ip_count) FILTER (WHERE mode = 'effective' AND event_at < $2), 0)::bigint AS rapid_ip_count
		FROM key_ip_sweep
		GROUP BY api_key_id
	),
shared_key_interval_ordered AS (
	SELECT
		ip,
		api_key_id,
		id,
		created_at AS start_at,
		created_at + INTERVAL '10 minutes' AS end_at,
		MAX(created_at + INTERVAL '10 minutes') OVER (
			PARTITION BY ip, api_key_id
			ORDER BY created_at, id
			ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
		) AS previous_end
	FROM window_logs
	WHERE ip IS NOT NULL
),
shared_key_interval_islands AS (
	SELECT x.*,
		SUM(CASE WHEN previous_end IS NULL OR start_at > previous_end THEN 1 ELSE 0 END) OVER (
			PARTITION BY ip, api_key_id
			ORDER BY start_at, id
			ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
		) AS island_no
	FROM shared_key_interval_ordered AS x
),
shared_key_ranges AS (
	SELECT ip, api_key_id, island_no, MIN(start_at) AS start_at, MAX(end_at) AS end_at
	FROM shared_key_interval_islands
	GROUP BY ip, api_key_id, island_no
),
shared_user_interval_ordered AS (
	SELECT
		ip,
		user_id,
		id,
		created_at AS start_at,
		created_at + INTERVAL '10 minutes' AS end_at,
		MAX(created_at + INTERVAL '10 minutes') OVER (
			PARTITION BY ip, user_id
			ORDER BY created_at, id
			ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
		) AS previous_end
	FROM window_logs
	WHERE ip IS NOT NULL
),
shared_user_interval_islands AS (
	SELECT x.*,
		SUM(CASE WHEN previous_end IS NULL OR start_at > previous_end THEN 1 ELSE 0 END) OVER (
			PARTITION BY ip, user_id
			ORDER BY start_at, id
			ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
		) AS island_no
	FROM shared_user_interval_ordered AS x
),
shared_user_ranges AS (
	SELECT ip, user_id, island_no, MIN(start_at) AS start_at, MAX(end_at) AS end_at
	FROM shared_user_interval_islands
	GROUP BY ip, user_id, island_no
),
shared_events AS (
	SELECT ip, start_at AS event_at, 1::bigint AS key_delta, 0::bigint AS user_delta FROM shared_key_ranges
	UNION ALL
	SELECT ip, end_at AS event_at, -1::bigint AS key_delta, 0::bigint AS user_delta FROM shared_key_ranges
	UNION ALL
	SELECT ip, start_at AS event_at, 0::bigint AS key_delta, 1::bigint AS user_delta FROM shared_user_ranges
	UNION ALL
	SELECT ip, end_at AS event_at, 0::bigint AS key_delta, -1::bigint AS user_delta FROM shared_user_ranges
),
	shared_event_deltas AS (
		SELECT ip, event_at, SUM(key_delta)::bigint AS key_delta, SUM(user_delta)::bigint AS user_delta
		FROM shared_events
		GROUP BY ip, event_at
	),
	shared_sweep_events AS (
		SELECT ip, event_at, SUM(key_delta)::bigint AS key_delta, SUM(user_delta)::bigint AS user_delta
		FROM (
			SELECT ip, event_at, key_delta, user_delta
			FROM shared_event_deltas
			WHERE event_at >= $1
			UNION ALL
			SELECT ip, $1::timestamptz AS event_at,
				SUM(key_delta)::bigint AS key_delta,
				SUM(user_delta)::bigint AS user_delta
			FROM shared_event_deltas
			WHERE event_at < $1
			GROUP BY ip
		) AS scoped_events
		GROUP BY ip, event_at
	),
	shared_sweep AS (
		SELECT ip, event_at,
			SUM(key_delta) OVER (PARTITION BY ip ORDER BY event_at ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)::bigint AS active_key_count,
			SUM(user_delta) OVER (PARTITION BY ip ORDER BY event_at ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)::bigint AS active_user_count
		FROM shared_sweep_events
	),
	shared_sweep_segments AS (
		SELECT ip,
			event_at AS start_at,
			LEAD(event_at) OVER (PARTITION BY ip ORDER BY event_at) AS end_at,
			active_key_count,
			active_user_count
		FROM shared_sweep
	),
	shared_risk_ranges AS (
		SELECT ip, start_at, end_at
		FROM shared_sweep_segments
		WHERE active_key_count >= 2
		  AND active_user_count >= 2
		  AND start_at < end_at
		  AND start_at < $2
		  AND end_at > $1
	),
	shared_observations AS (
		SELECT DISTINCT c.api_key_id, c.id, c.ip, c.created_at
		FROM current_logs AS c
		JOIN shared_risk_ranges AS srr
		  ON srr.ip = c.ip
		 AND c.created_at < srr.end_at
		 AND c.created_at + INTERVAL '10 minutes' > srr.start_at
		WHERE c.ip IS NOT NULL
	),
	ip_trust AS (
		SELECT
			b.*,
			(NOT b.seen_before AND (b.has_prior_valid_ip OR b.ip_rank > 1)) AS raw_new,
			EXISTS (
			SELECT 1
			FROM key_ip_audit_trusted_ips AS t
			WHERE t.api_key_id = b.api_key_id
			  AND (t.expires_at IS NULL OR t.expires_at > NOW())
			  AND try_inet(NULLIF(BTRIM(b.ip), '')) <<= t.cidr::inet
			) AS trusted,
			EXISTS (
				SELECT 1
				FROM shared_observations AS so
				WHERE so.api_key_id = b.api_key_id
				  AND so.ip = b.ip
			) AS raw_shared
		FROM key_ip_baseline AS b
	),
	ip_flags AS (
		SELECT
			i.*,
			CASE WHEN i.raw_new AND NOT i.trusted AND EXISTS (
				SELECT 1
				FROM current_logs AS c
				WHERE c.api_key_id = i.api_key_id
				  AND c.ip = i.ip
				  AND NOT EXISTS (
					SELECT 1
					FROM key_ip_audit_dismissals AS d
					WHERE d.api_key_id = i.api_key_id
					  AND d.risk_code = 'new_ip'
					  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = c.ip
					  AND d.event_start <= c.created_at
					  AND d.event_end > c.created_at
				  )
			) THEN TRUE ELSE FALSE END AS effective_new,
			CASE WHEN i.raw_shared AND EXISTS (
				SELECT 1
				FROM shared_observations AS so
				WHERE so.api_key_id = i.api_key_id
				  AND so.ip = i.ip
				  AND NOT EXISTS (
					SELECT 1
					FROM key_ip_audit_dismissals AS d
					WHERE d.api_key_id = i.api_key_id
					  AND d.risk_code = 'shared_ip_cross_users'
					  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = so.ip
					  AND d.event_start <= so.created_at
					  AND d.event_end > so.created_at
				  )
			) THEN TRUE ELSE FALSE END AS effective_shared,
			CASE WHEN i.raw_new AND NOT i.trusted AND NOT EXISTS (
				SELECT 1
				FROM current_logs AS c
				WHERE c.api_key_id = i.api_key_id
				  AND c.ip = i.ip
				  AND NOT EXISTS (
					SELECT 1
					FROM key_ip_audit_dismissals AS d
					WHERE d.api_key_id = i.api_key_id
					  AND d.risk_code = 'new_ip'
					  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = c.ip
					  AND d.event_start <= c.created_at
					  AND d.event_end > c.created_at
				  )
			) THEN TRUE ELSE FALSE END AS new_ip_dismissed,
			CASE WHEN i.raw_shared AND NOT EXISTS (
				SELECT 1
				FROM shared_observations AS so
				WHERE so.api_key_id = i.api_key_id
				  AND so.ip = i.ip
				  AND NOT EXISTS (
					SELECT 1
					FROM key_ip_audit_dismissals AS d
					WHERE d.api_key_id = i.api_key_id
					  AND d.risk_code = 'shared_ip_cross_users'
					  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = so.ip
					  AND d.event_start <= so.created_at
					  AND d.event_end > so.created_at
				  )
			) THEN TRUE ELSE FALSE END AS shared_ip_dismissed
		FROM ip_trust AS i
	),
ip_counts AS (
	SELECT
		api_key_id,
		COUNT(*)::bigint AS ip_count,
			COUNT(*) FILTER (WHERE raw_new)::bigint AS raw_new_ip_count,
			COUNT(*) FILTER (WHERE effective_new)::bigint AS new_ip_count,
			COUNT(*) FILTER (WHERE raw_shared)::bigint AS raw_shared_ip_count,
			COUNT(*) FILTER (WHERE effective_shared)::bigint AS shared_ip_count,
			BOOL_OR(new_ip_dismissed) AS new_ip_dismissed,
			BOOL_OR(shared_ip_dismissed) AS shared_ip_dismissed
	FROM ip_flags
	GROUP BY api_key_id
),
volume_flags AS (
	SELECT
		cks.api_key_id,
		CASE WHEN cks.request_count >= 20 AND (
			(COALESCE(pks.request_count, 0) = 0 AND cks.request_count >= 50) OR
			(COALESCE(pks.request_count, 0) > 0 AND cks.request_count >= pks.request_count * 3 AND cks.request_count - pks.request_count >= 20)
		) AND (
			COALESCE(pks.request_count, 0) > 0 OR COALESCE(ic.raw_new_ip_count, 0) > 0 OR COALESCE(rb.raw_rapid_ip_count, 0) >= 3
		) THEN TRUE ELSE FALSE END AS raw_volume_spike,
		CASE WHEN COALESCE(vc.request_count, 0) >= 20 AND (
			(COALESCE(vp.request_count, 0) = 0 AND COALESCE(vc.request_count, 0) >= 50) OR
			(COALESCE(vp.request_count, 0) > 0 AND COALESCE(vc.request_count, 0) >= vp.request_count * 3 AND COALESCE(vc.request_count, 0) - vp.request_count >= 20)
		) AND (
			COALESCE(vp.request_count, 0) > 0 OR COALESCE(ic.new_ip_count, 0) > 0 OR COALESCE(rb.rapid_ip_count, 0) >= 3
			) THEN TRUE ELSE FALSE END AS volume_spike,
			COALESCE(vc.request_count, 0)::bigint AS effective_current_request_count,
			COALESCE(vp.request_count, 0)::bigint AS effective_prior_request_count,
			(
				COALESCE(vc.request_count, 0) < cks.request_count
				OR COALESCE(vp.request_count, 0) < COALESCE(pks.request_count, 0)
			) AS volume_dismissed
	FROM current_key_stats AS cks
	LEFT JOIN prior_key_stats AS pks ON pks.api_key_id = cks.api_key_id
	LEFT JOIN volume_current_key_stats AS vc ON vc.api_key_id = cks.api_key_id
	LEFT JOIN volume_prior_key_stats AS vp ON vp.api_key_id = cks.api_key_id
	LEFT JOIN ip_counts AS ic ON ic.api_key_id = cks.api_key_id
	LEFT JOIN rapid_by_key AS rb ON rb.api_key_id = cks.api_key_id
),
latest_ip AS (
	SELECT DISTINCT ON (api_key_id) api_key_id, ip
	FROM current_logs
	WHERE ip IS NOT NULL
	ORDER BY api_key_id, created_at DESC, id DESC
),
key_rows AS (
	SELECT
		ck.key_id,
		ck.key_name,
		ck.key_prefix,
		ck.key_status,
		ck.owner_user_id AS user_id,
		ck.user_email,
		li.ip AS latest_ip,
		COALESCE(ic.ip_count, 0)::bigint AS ip_count,
		COALESCE(ic.raw_new_ip_count, 0)::bigint AS raw_new_ip_count,
		COALESCE(ic.new_ip_count, 0)::bigint AS new_ip_count,
		cks.first_seen,
		cks.last_seen,
		cks.request_count,
		COALESCE(pks.request_count, 0)::bigint AS prior_request_count,
		COALESCE(rb.raw_rapid_ip_count, 0)::bigint AS raw_rapid_ip_count,
		COALESCE(rb.rapid_ip_count, 0)::bigint AS rapid_ip_count,
		COALESCE(ic.raw_shared_ip_count, 0)::bigint AS raw_shared_ip_count,
		COALESCE(ic.shared_ip_count, 0)::bigint AS shared_ip_count,
		vf.raw_volume_spike,
			vf.volume_spike,
			vf.effective_current_request_count,
			vf.effective_prior_request_count,
			(
				(COALESCE(ic.new_ip_dismissed, FALSE)
				 AND COALESCE(ic.raw_new_ip_count, 0) > 0
				 AND COALESCE(ic.new_ip_count, 0) = 0)
				OR (COALESCE(rb.raw_rapid_ip_count, 0) >= 3
				 AND COALESCE(rb.rapid_ip_count, 0) < 3)
				OR (COALESCE(ic.shared_ip_dismissed, FALSE)
				 AND COALESCE(ic.raw_shared_ip_count, 0) > 0
				 AND COALESCE(ic.shared_ip_count, 0) = 0)
				OR (vf.raw_volume_spike AND NOT vf.volume_spike AND vf.volume_dismissed)
			) AS has_dismissal
	FROM candidate_keys AS ck
	JOIN current_key_stats AS cks ON cks.api_key_id = ck.key_id
	LEFT JOIN prior_key_stats AS pks ON pks.api_key_id = ck.key_id
	LEFT JOIN latest_ip AS li ON li.api_key_id = ck.key_id
	LEFT JOIN ip_counts AS ic ON ic.api_key_id = ck.key_id
	LEFT JOIN rapid_by_key AS rb ON rb.api_key_id = ck.key_id
	LEFT JOIN volume_flags AS vf ON vf.api_key_id = ck.key_id
),
risk_scored AS (
	SELECT r.*,
		CASE
			WHEN r.rapid_ip_count >= 3 OR (r.new_ip_count > 0 AND r.volume_spike) THEN 'high'
			WHEN r.new_ip_count > 0 OR r.shared_ip_count > 0 OR r.volume_spike THEN 'medium'
			ELSE 'none'
		END AS risk_level,
		CASE
			WHEN r.raw_rapid_ip_count >= 3 OR r.raw_new_ip_count > 0 OR r.raw_shared_ip_count > 0 OR r.raw_volume_spike THEN TRUE
			ELSE FALSE
		END AS raw_risk
	FROM key_rows AS r
),
scored AS (
	SELECT s.*,
		CASE
			WHEN s.risk_level <> 'none' THEN 'open'
			WHEN s.raw_risk AND s.has_dismissal THEN 'dismissed'
			ELSE 'normal'
		END AS audit_status
	FROM risk_scored AS s
)`

func keyIPAuditArgs(filter service.KeyIPAuditFilter) []any {
	duration := filter.EndTime.Sub(filter.StartTime)
	return []any{
		filter.StartTime.UTC(),
		filter.EndTime.UTC(),
		filter.StartTime.Add(-duration).UTC(),
		filter.APIKeyID,
		filter.UserID,
		strings.ToLower(strings.TrimSpace(filter.KeyQuery)),
		strings.ToLower(strings.TrimSpace(filter.UserQuery)),
		strings.TrimSpace(filter.IP),
		strings.ToLower(strings.TrimSpace(filter.Risk)),
		strings.ToLower(strings.TrimSpace(filter.Status)),
		strings.ToLower(strings.TrimSpace(filter.Signal)),
	}
}

func keyIPAuditFinalConditions(alias string) string {
	return fmt.Sprintf(`
		($8 = '' OR EXISTS (
			SELECT 1 FROM current_logs AS ip_filter
			WHERE ip_filter.api_key_id = %[1]s.key_id AND ip_filter.ip = $8
		))
		AND (
			$9 = '' OR $9 = 'all' OR
			($9 = 'none' AND %[1]s.risk_level = 'none') OR
			($9 = 'low' AND %[1]s.risk_level = 'low') OR
			($9 = 'medium' AND %[1]s.risk_level = 'medium') OR
			($9 = 'high' AND %[1]s.risk_level = 'high')
		)
		AND (
			$11 = '' OR $11 = 'all' OR
			($11 = 'new_ip' AND %[1]s.new_ip_count > 0) OR
			($11 = 'multi_ip_burst' AND %[1]s.rapid_ip_count >= 3) OR
			($11 = 'shared_ip_cross_users' AND %[1]s.shared_ip_count > 0) OR
			($11 = 'volume_spike' AND %[1]s.volume_spike)
		)
		AND ($12 = 0 OR %[1]s.key_id <> $12)`, alias)
}

func keyIPAuditFinalWhere(alias string) string {
	return "WHERE " + keyIPAuditFinalConditions(alias)
}

const keyIPAuditKeySelect = `
	s.key_id,
	s.key_name,
	s.key_prefix,
	s.key_status,
	s.user_id,
	s.user_email,
	s.latest_ip,
	s.ip_count,
	s.new_ip_count,
	s.first_seen,
	s.last_seen,
	s.request_count,
	s.prior_request_count,
	s.raw_new_ip_count,
	s.raw_rapid_ip_count,
	s.rapid_ip_count,
	s.raw_shared_ip_count,
	s.shared_ip_count,
	s.raw_volume_spike,
	s.volume_spike,
	s.effective_current_request_count,
	s.effective_prior_request_count,
	s.has_dismissal`

func (r *keyIPAuditRepository) ListKeys(ctx context.Context, filter service.KeyIPAuditFilter) (*service.KeyIPAuditKeyList, error) {
	readCtx, cancel, tx, err := r.beginKeyIPAuditRead(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()

	result, err := r.listKeys(readCtx, tx, filter, 0)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *keyIPAuditRepository) beginKeyIPAuditRead(ctx context.Context) (context.Context, context.CancelFunc, *sql.Tx, error) {
	if r == nil || r.db == nil {
		return nil, nil, nil, errors.New("nil key/ip audit repository")
	}
	readCtx, cancel := context.WithTimeout(ctx, keyIPAuditReadTimeout)
	tx, err := r.db.BeginTx(readCtx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if _, err := tx.ExecContext(readCtx, `SET LOCAL statement_timeout = '30000ms'`); err != nil {
		_ = tx.Rollback()
		cancel()
		return nil, nil, nil, err
	}
	return readCtx, cancel, tx, nil
}

func (r *keyIPAuditRepository) listKeys(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, excludeKeyID int64) (*service.KeyIPAuditKeyList, error) {
	args := keyIPAuditArgs(filter)
	args = append(args, excludeKeyID)
	where := keyIPAuditFinalWhere("s")

	var total int64
	if err := scanSingleRow(ctx, q, keyIPAuditBaseCTE+` SELECT COUNT(*) FROM scored AS s `+where, args, &total); err != nil {
		return nil, err
	}

	query := keyIPAuditBaseCTE + fmt.Sprintf(`
		SELECT %s
		FROM scored AS s
		%s
		ORDER BY CASE s.risk_level WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END DESC,
			s.last_seen DESC, s.key_id ASC
			LIMIT $13 OFFSET $14`, keyIPAuditKeySelect, where)
	listArgs := append(append([]any{}, args...), filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := q.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, err
	}
	items := make([]service.KeyIPAuditKeyRow, 0, filter.PageSize)
	for rows.Next() {
		aggregate, scanErr := scanKeyIPAuditKeyAggregate(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		items = append(items, service.KeyIPAuditKeyRowFromAggregate(*aggregate))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	summary, err := r.queryKeyIPAuditKeySummary(ctx, q, filter, excludeKeyID)
	if err != nil {
		return nil, err
	}
	coverage, err := r.queryKeyIPAuditCoverage(ctx, q, filter, excludeKeyID)
	if err != nil {
		return nil, err
	}
	trend, err := r.queryKeyIPAuditTrend(ctx, q, filter, excludeKeyID)
	if err != nil {
		return nil, err
	}
	return &service.KeyIPAuditKeyList{
		Items:    items,
		Total:    total,
		Page:     filter.Page,
		PageSize: filter.PageSize,
		Summary:  *summary,
		Trend:    trend,
		Metadata: service.KeyIPAuditMetadata{From: filter.StartTime, To: filter.EndTime, Coverage: *coverage},
	}, nil
}

func scanKeyIPAuditKeyAggregate(scanner interface{ Scan(...any) error }) (*service.KeyIPAuditKeyAggregate, error) {
	var (
		a          service.KeyIPAuditKeyAggregate
		latestIP   sql.NullString
		rawNew    int64
		rawVolume bool
		volume     bool
		hasDismiss bool
	)
	if err := scanner.Scan(
		&a.KeyID,
		&a.KeyName,
		&a.KeyPrefix,
		&a.KeyStatus,
		&a.UserID,
		&a.UserEmail,
		&latestIP,
		&a.IPCount,
		&a.NewIPCount,
		&a.FirstSeen,
		&a.LastSeen,
		&a.RequestCount,
		&a.PriorRequestCount,
		&rawNew,
		&a.RawRapidIPCount,
		&a.RapidIPCount,
		&a.RawSharedIPCount,
		&a.SharedIPCount,
		&rawVolume,
		&volume,
		&a.CurrentRequestCount,
		&a.PriorRequestCountForRisk,
		&hasDismiss,
	); err != nil {
		return nil, err
	}
	if latestIP.Valid {
		value := latestIP.String
		a.LatestIP = &value
	}
	a.RawNewIPCount = rawNew
	a.VolumeSpike = volume
	a.RawVolumeSpike = rawVolume
	a.DismissedAny = hasDismiss
	return &a, nil
}

func (r *keyIPAuditRepository) queryKeyIPAuditKeySummary(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, excludeKeyID int64) (*service.KeyIPAuditKeySummary, error) {
	args := keyIPAuditArgs(filter)
	args = append(args, excludeKeyID)
	conditions := keyIPAuditFinalConditions("s")
	sharedConditions := keyIPAuditFinalConditions("ss")
	query := keyIPAuditBaseCTE + fmt.Sprintf(`
		SELECT
			COUNT(*)::bigint,
			COUNT(*) FILTER (WHERE s.risk_level = 'high')::bigint,
			COUNT(*) FILTER (WHERE s.new_ip_count > 0)::bigint,
			COUNT(*) FILTER (WHERE s.rapid_ip_count >= 3)::bigint,
			(
				SELECT COUNT(DISTINCT f.ip)::bigint
				FROM ip_flags AS f
				JOIN scored AS ss ON ss.key_id = f.api_key_id
				WHERE f.effective_shared
				  AND ($8 = '' OR f.ip = $8)
				  AND %s
			),
			COUNT(*) FILTER (WHERE s.audit_status = 'open')::bigint
		FROM scored AS s
		WHERE %s`, sharedConditions, conditions)
	var summary service.KeyIPAuditKeySummary
	if err := scanSingleRow(ctx, q, query, args, &summary.TotalKeys, &summary.HighRiskKeys, &summary.NewIPKeys, &summary.MultiIPKeys, &summary.SharedIPs, &summary.PendingKeys); err != nil {
		return nil, err
	}
	return &summary, nil
}

func (r *keyIPAuditRepository) queryKeyIPAuditCoverage(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, excludeKeyID int64) (*service.KeyIPAuditCoverage, error) {
	args := keyIPAuditArgs(filter)
	args = append(args, excludeKeyID)
	conditions := keyIPAuditFinalConditions("s")
	query := keyIPAuditBaseCTE + fmt.Sprintf(`
		SELECT
			COUNT(*)::bigint,
			COUNT(*) FILTER (WHERE c.ip IS NULL)::bigint,
			COUNT(*) FILTER (WHERE c.user_agent IS NULL)::bigint
		FROM current_logs AS c
		JOIN scored AS s ON s.key_id = c.api_key_id
		WHERE ($8 = '' OR c.ip = $8)
		  AND %s`, conditions)
	var total, missingIP, missingUA int64
	if err := scanSingleRow(ctx, q, query, args, &total, &missingIP, &missingUA); err != nil {
		return nil, err
	}
	coverage := &service.KeyIPAuditCoverage{
		Source:                "usage_logs",
		UsageLogCount:         total,
		MissingIPCount:        missingIP,
		MissingUserAgentCount: missingUA,
	}
	if total > 0 {
		coverage.IPCoveragePercent = float64(total-missingIP) * 100 / float64(total)
	}
	return coverage, nil
}

func (r *keyIPAuditRepository) queryKeyIPAuditTrend(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, excludeKeyID int64) ([]service.KeyIPAuditTrendPoint, error) {
	bucket := "hour"
	if filter.EndTime.Sub(filter.StartTime) > 48*time.Hour {
		bucket = "day"
	}
	args := keyIPAuditArgs(filter)
	args = append(args, excludeKeyID)
	conditions := keyIPAuditFinalConditions("s")
	query := keyIPAuditBaseCTE + fmt.Sprintf(`
		SELECT date_trunc('%s', c.created_at) AS bucket_start,
			COUNT(*)::bigint,
			COUNT(DISTINCT c.api_key_id) FILTER (WHERE s.risk_level <> 'none')::bigint
		FROM current_logs AS c
		JOIN scored AS s ON s.key_id = c.api_key_id
		WHERE ($8 = '' OR c.ip = $8)
		  AND %s
		GROUP BY 1
		ORDER BY 1`, bucket, conditions)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	trend := make([]service.KeyIPAuditTrendPoint, 0)
	for rows.Next() {
		var point service.KeyIPAuditTrendPoint
		if err := rows.Scan(&point.BucketStart, &point.RequestCount, &point.RiskyKeys); err != nil {
			_ = rows.Close()
			return nil, err
		}
		trend = append(trend, point)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return trend, nil
}

func (r *keyIPAuditRepository) KeyDetail(ctx context.Context, filter service.KeyIPAuditFilter, ipPage, ipPageSize int, relatedIP string, relatedPage, relatedPageSize int) (*service.KeyIPAuditKeyDetail, error) {
	readCtx, cancel, tx, err := r.beginKeyIPAuditRead(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()

	keyFilter := filter
	keyFilter.Page = 1
	keyFilter.PageSize = 1
	keyList, err := r.listKeys(readCtx, tx, keyFilter, 0)
	if err != nil {
		return nil, err
	}
	if len(keyList.Items) == 0 {
		return nil, service.ErrAPIKeyNotFound
	}

	ips, ipsTotal, err := r.queryKeyIPAuditIPs(readCtx, tx, filter, ipPage, ipPageSize)
	if err != nil {
		return nil, err
	}
	if relatedIP == "" && keyList.Items[0].LatestIP != nil {
		relatedIP = *keyList.Items[0].LatestIP
	}
	relatedKeys := make([]service.KeyIPAuditKeyRow, 0)
	var relatedTotal int64
	if relatedIP != "" {
		used, err := r.keyUsedIP(readCtx, tx, filter.APIKeyID, filter.StartTime, filter.EndTime, relatedIP)
		if err != nil {
			return nil, err
		}
		if used {
			relatedFilter := filter
			relatedFilter.APIKeyID = 0
			relatedFilter.IP = relatedIP
			relatedFilter.Page = relatedPage
			relatedFilter.PageSize = relatedPageSize
			relatedList, err := r.listKeys(readCtx, tx, relatedFilter, filter.APIKeyID)
			if err != nil {
				return nil, err
			}
			relatedKeys = relatedList.Items
			relatedTotal = relatedList.Total
		}
	}

	trustedRules, trustedTotal, err := r.listTrusted(readCtx, tx, filter.APIKeyID, 1, service.KeyIPAuditMaxPageSize)
	if err != nil {
		return nil, err
	}
	result := &service.KeyIPAuditKeyDetail{
		Key:             keyList.Items[0],
		IPs:             ips,
		IPsTotal:        ipsTotal,
		IPsPage:         ipPage,
		IPsPageSize:     ipPageSize,
		RelatedKeys:     relatedKeys,
		RelatedTotal:    relatedTotal,
		RelatedPage:     relatedPage,
		RelatedPageSize: relatedPageSize,
		RelatedIP:       relatedIP,
		TrustedRules:    trustedRules,
		TrustedTotal:    trustedTotal,
		Trend:           keyList.Trend,
		Metadata:        keyList.Metadata,
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

const keyIPAuditIPCTE = `
WITH current_ip_stats AS (
	SELECT
		host(try_inet(NULLIF(BTRIM(ul.ip_address), ''))) AS ip,
		MIN(ul.created_at) AS first_seen,
		MAX(ul.created_at) AS last_seen,
		COUNT(*)::bigint AS request_count,
		COUNT(DISTINCT NULLIF(BTRIM(COALESCE(ul.user_agent, '')), ''))::bigint AS user_agent_count,
		MIN(COALESCE(NULLIF(BTRIM(COALESCE(ul.user_agent, '')), ''), '')) AS user_agent
	FROM usage_logs AS ul
	WHERE ul.api_key_id = $3 AND ul.created_at >= $1 AND ul.created_at < $2
	  AND try_inet(NULLIF(BTRIM(ul.ip_address), '')) IS NOT NULL
	GROUP BY host(try_inet(NULLIF(BTRIM(ul.ip_address), '')))
),
ranked AS (
	SELECT i.*, ROW_NUMBER() OVER (ORDER BY first_seen, ip) AS ip_rank
	FROM current_ip_stats AS i
),
flags AS (
	SELECT r.*,
		EXISTS (
			SELECT 1 FROM usage_logs AS h
			WHERE h.api_key_id = $3 AND h.created_at < $1
			  AND host(try_inet(NULLIF(BTRIM(h.ip_address), ''))) = r.ip
		) AS seen_before,
		EXISTS (
			SELECT 1 FROM usage_logs AS h
			WHERE h.api_key_id = $3 AND h.created_at < $1
			  AND try_inet(NULLIF(BTRIM(h.ip_address), '')) IS NOT NULL
		) AS has_prior_valid_ip
	FROM ranked AS r
),
	trusted AS (
		SELECT f.*,
			EXISTS (
				SELECT 1 FROM key_ip_audit_trusted_ips AS t
				WHERE t.api_key_id = $3
				  AND (t.expires_at IS NULL OR t.expires_at > NOW())
				  AND try_inet(NULLIF(BTRIM(f.ip), '')) <<= t.cidr::inet
			) AS trusted,
			NOT EXISTS (
				SELECT 1
				FROM usage_logs AS c
				WHERE c.api_key_id = $3
				  AND c.created_at >= $1
				  AND c.created_at < $2
				  AND host(try_inet(NULLIF(BTRIM(c.ip_address), ''))) = f.ip
				  AND NOT EXISTS (
					SELECT 1 FROM key_ip_audit_dismissals AS d
					WHERE d.api_key_id = $3
					  AND d.risk_code = 'new_ip'
					  AND host(try_inet(NULLIF(BTRIM(d.ip_address), ''))) = f.ip
					  AND d.event_start <= c.created_at
					  AND d.event_end > c.created_at
				  )
			) AS new_ip_dismissed
		FROM flags AS f
	)
`

func (r *keyIPAuditRepository) queryKeyIPAuditIPs(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, page, pageSize int) ([]service.KeyIPAuditIPRow, int64, error) {
	var total int64
	if err := scanSingleRow(ctx, q, keyIPAuditIPCTE+` SELECT COUNT(*) FROM flags`, []any{filter.StartTime, filter.EndTime, filter.APIKeyID}, &total); err != nil {
		return nil, 0, err
	}
	query := keyIPAuditIPCTE + `
		SELECT ip, first_seen, last_seen, request_count, user_agent, user_agent_count,
			CASE WHEN NOT seen_before AND (has_prior_valid_ip OR ip_rank > 1) AND NOT trusted AND NOT new_ip_dismissed THEN TRUE ELSE FALSE END,
			trusted
		FROM trusted
		ORDER BY last_seen DESC, ip ASC
		LIMIT $4 OFFSET $5`
	rows, err := q.QueryContext(ctx, query, filter.StartTime, filter.EndTime, filter.APIKeyID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	items := make([]service.KeyIPAuditIPRow, 0, pageSize)
	for rows.Next() {
		var item service.KeyIPAuditIPRow
		if err := rows.Scan(&item.IP, &item.FirstSeen, &item.LastSeen, &item.RequestCount, &item.UserAgent, &item.UserAgentCount, &item.NewIP, &item.Trusted); err != nil {
			_ = rows.Close()
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *keyIPAuditRepository) keyUsedIP(ctx context.Context, q sqlQueryer, keyID int64, from, to time.Time, ip string) (bool, error) {
	var used bool
	err := scanSingleRow(ctx, q, `
		SELECT EXISTS (
			SELECT 1 FROM usage_logs
			WHERE api_key_id = $1 AND created_at >= $2 AND created_at < $3
			  AND host(try_inet(NULLIF(BTRIM(ip_address), ''))) = $4
		)`, []any{keyID, from, to, ip}, &used)
	return used, err
}

func (r *keyIPAuditRepository) ListTrusted(ctx context.Context, apiKeyID int64, page, pageSize int) ([]service.KeyIPAuditTrustedRule, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New("nil key/ip audit repository")
	}
	readCtx, cancel := context.WithTimeout(ctx, keyIPAuditReadTimeout)
	defer cancel()
	return r.listTrusted(readCtx, r.db, apiKeyID, page, pageSize)
}

func (r *keyIPAuditRepository) listTrusted(ctx context.Context, q sqlQueryer, apiKeyID int64, page, pageSize int) ([]service.KeyIPAuditTrustedRule, int64, error) {
	var total int64
	if err := scanSingleRow(ctx, q, `SELECT COUNT(*) FROM key_ip_audit_trusted_ips WHERE ($1 = 0 OR api_key_id = $1)`, []any{apiKeyID}, &total); err != nil {
		return nil, 0, err
	}
	rows, err := q.QueryContext(ctx, `
		SELECT id, api_key_id, cidr, note, expires_at, created_by, created_at
		FROM key_ip_audit_trusted_ips
		WHERE ($1 = 0 OR api_key_id = $1)
		ORDER BY api_key_id, id
		LIMIT $2 OFFSET $3`, apiKeyID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	items := make([]service.KeyIPAuditTrustedRule, 0, pageSize)
	for rows.Next() {
		var item service.KeyIPAuditTrustedRule
		if err := rows.Scan(&item.ID, &item.APIKeyID, &item.CIDR, &item.Note, &item.ExpiresAt, &item.CreatedBy, &item.CreatedAt); err != nil {
			_ = rows.Close()
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (r *keyIPAuditRepository) CreateTrusted(ctx context.Context, input service.KeyIPAuditTrustedInput) (*service.KeyIPAuditTrustedRule, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("nil key/ip audit repository")
	}
	query := `
		INSERT INTO key_ip_audit_trusted_ips (api_key_id, cidr, note, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (api_key_id, cidr) DO UPDATE SET
			note = EXCLUDED.note, expires_at = EXCLUDED.expires_at
		RETURNING id, api_key_id, cidr, note, expires_at, created_by, created_at`
	var item service.KeyIPAuditTrustedRule
	if err := scanSingleRow(ctx, r.db, query, []any{input.APIKeyID, input.CIDR, input.Note, input.ExpiresAt, input.CreatedBy}, &item.ID, &item.APIKeyID, &item.CIDR, &item.Note, &item.ExpiresAt, &item.CreatedBy, &item.CreatedAt); err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrAPIKeyNotFoundForKeyIPAudit()
		}
		return nil, err
	}
	return &item, nil
}

func (r *keyIPAuditRepository) DeleteTrusted(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("nil key/ip audit repository")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM key_ip_audit_trusted_ips WHERE id = $1`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return service.ErrKeyIPAuditTrustedNotFound
	}
	return nil
}

func (r *keyIPAuditRepository) CreateDismissal(ctx context.Context, input service.KeyIPAuditDismissalInput) (*service.KeyIPAuditDismissal, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("nil key/ip audit repository")
	}
	query := `
		INSERT INTO key_ip_audit_dismissals (api_key_id, ip_address, risk_code, event_start, event_end, note, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, api_key_id, ip_address, risk_code, event_start, event_end, note, created_by, created_at`
	var item service.KeyIPAuditDismissal
	if err := scanSingleRow(ctx, r.db, query, []any{input.APIKeyID, input.IP, input.RiskCode, input.EventStart, input.EventEnd, input.Note, input.CreatedBy}, &item.ID, &item.APIKeyID, &item.IP, &item.RiskCode, &item.EventStart, &item.EventEnd, &item.Note, &item.CreatedBy, &item.CreatedAt); err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrAPIKeyNotFoundForKeyIPAudit()
		}
		return nil, err
	}
	return &item, nil
}

func (r *keyIPAuditRepository) DeleteDismissal(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("nil key/ip audit repository")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM key_ip_audit_dismissals WHERE id = $1`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return service.ErrKeyIPAuditDismissalNotFound
	}
	return nil
}

// Kept as a small indirection so the repository does not introduce a second
// API-key error value or a dependency on repository-owned error types.
func ErrAPIKeyNotFoundForKeyIPAudit() error {
	return service.ErrAPIKeyNotFound
}
