package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// keyIPAuditMaterializedCTE intentionally reads only the future-only security
// projection. The API may still accept the historical-looking `from`/`to`
// contract, but ranges before live_since are reported as uncovered instead of
// silently scanning usage_logs.
const keyIPAuditCandidateKeys = `
	SELECT k.id AS key_id,
	       k.name AS key_name,
	       CASE WHEN k.deleted_at IS NOT NULL THEN 'deleted' ELSE LOWER(k.status) END AS key_status,
	       k.user_id AS owner_user_id,
	       COALESCE(u.email, '') AS user_email,
	       CASE WHEN LENGTH(k.key) <= 8 THEN LEFT(k.key, 3) || '***' ELSE LEFT(k.key, 8) || '...' END AS key_prefix
	FROM api_keys k
	LEFT JOIN users u ON u.id = k.user_id
	WHERE ($4 = 0 OR k.id = $4)
	  AND ($5 = 0 OR k.user_id = $5)
	  AND ($6 = '' OR k.name ILIKE '%' || $6 || '%' OR k.id::text ILIKE '%' || $6 || '%')
	  AND ($7 = '' OR COALESCE(u.email, '') ILIKE '%' || $7 || '%' OR k.user_id::text ILIKE '%' || $7 || '%')
	  AND ($10::text = '' OR ($10::text = 'inactive' AND LOWER(COALESCE(k.status, '')) <> 'active')
	       OR LOWER(CASE WHEN k.deleted_at IS NOT NULL THEN 'deleted' ELSE k.status END) = $10::text)
	  AND ($9::text IS NULL OR $9::text IS NOT NULL)
	  AND ($8::text IS NULL OR $8::text IS NOT NULL)
	  AND ($11::text IS NULL OR $11::text IS NOT NULL)
	  AND ($3::timestamptz IS NULL OR $3::timestamptz IS NOT NULL)`

var keyIPAuditMaterializedCTE = `
WITH candidate_keys AS (
	` + keyIPAuditCandidateKeys + `
), current_facts AS NOT MATERIALIZED (
	SELECT * FROM key_ip_audit_current_facts
), prior_facts AS (
	` + keyIPAuditPriorFacts + `
), current_key_stats AS (
	SELECT api_key_id, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
	       SUM(request_count)::bigint AS request_count,
	       SUM(missing_ip_count)::bigint AS missing_ip_count,
	       SUM(missing_user_agent_count)::bigint AS missing_user_agent_count
	FROM current_facts GROUP BY api_key_id
), prior_key_stats AS (
	SELECT api_key_id, SUM(request_count)::bigint AS request_count
	FROM prior_facts GROUP BY api_key_id
), current_ip_stats AS (
	SELECT api_key_id, client_ip, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
	       SUM(request_count)::bigint AS request_count,
	       COUNT(DISTINCT NULLIF(user_agent, ''))::bigint AS user_agent_count,
	       COALESCE(MIN(NULLIF(user_agent, '')), '') AS user_agent
	FROM current_facts WHERE client_ip <> ''
	GROUP BY api_key_id, client_ip
), current_buckets AS (
	SELECT DISTINCT api_key_id, bucket_start, bucket_end FROM current_facts
), edge_buckets AS (
	SELECT api_key_id, bucket_start FROM current_buckets
	WHERE bucket_start < $1 OR bucket_end > $2
), edge_shared AS (
	SELECT DISTINCT b.api_key_id, b.bucket_start, e.client_ip
	FROM edge_buckets b
	JOIN security_activity_events e
	  ON e.api_key_id = b.api_key_id
	 AND e.created_at >= GREATEST(b.bucket_start, $1::timestamptz)
	 AND e.created_at < LEAST(b.bucket_start + INTERVAL '1 minute', $2::timestamptz)
	 AND e.client_ip <> '' AND e.user_id <> 0
	JOIN security_activity_events other
	  ON other.client_ip = e.client_ip AND other.user_id <> 0
	 AND other.api_key_id <> e.api_key_id
	 AND other.user_id <> e.user_id
	 AND other.created_at >= e.created_at - INTERVAL '10 minutes'
	 AND other.created_at < LEAST(b.bucket_start + INTERVAL '1 minute', $2::timestamptz)
), edge_rapid_counts AS (
	SELECT b.api_key_id, b.bucket_start, anchor.created_at,
	       COUNT(DISTINCT context_event.client_ip)::bigint AS rapid_ip_count
	FROM edge_buckets b
	JOIN security_activity_events anchor
	  ON anchor.api_key_id = b.api_key_id
	 AND anchor.created_at >= GREATEST(b.bucket_start, $1::timestamptz)
	 AND anchor.created_at < LEAST(b.bucket_start + INTERVAL '1 minute', $2::timestamptz)
	JOIN security_activity_events context_event
	  ON context_event.api_key_id = anchor.api_key_id
	 AND context_event.client_ip <> ''
	 AND context_event.created_at >= anchor.created_at - INTERVAL '10 minutes'
	 AND context_event.created_at <= anchor.created_at
	GROUP BY b.api_key_id, b.bucket_start, anchor.created_at
), edge_rapid AS (
	SELECT api_key_id, bucket_start, MAX(rapid_ip_count)::bigint AS rapid_ip_count
	FROM edge_rapid_counts GROUP BY api_key_id, bucket_start
), raw_rapid_buckets AS (
	SELECT b.api_key_id, b.bucket_start,
	       CASE WHEN eb.bucket_start IS NOT NULL THEN COALESCE(er.rapid_ip_count, 0)
	            ELSE COALESCE(m.raw_rapid_ip_count, mr.raw_rapid_ip_count, 0) END::bigint AS raw_rapid_ip_count
	FROM current_buckets b
	LEFT JOIN edge_buckets eb ON eb.api_key_id=b.api_key_id AND eb.bucket_start=b.bucket_start
	LEFT JOIN edge_rapid er ON er.api_key_id=b.api_key_id AND er.bucket_start=b.bucket_start
	LEFT JOIN LATERAL (SELECT m.raw_rapid_ip_count FROM key_ip_audit_key_1m m
	 WHERE b.bucket_end=b.bucket_start+INTERVAL '1 minute'
	   AND m.api_key_id=b.api_key_id AND m.bucket_start=b.bucket_start LIMIT 1) m ON TRUE
	LEFT JOIN LATERAL (SELECT mr.raw_rapid_ip_count FROM key_ip_audit_key_rollups mr
	 WHERE b.bucket_end>b.bucket_start+INTERVAL '1 minute'
	   AND mr.api_key_id=b.api_key_id AND mr.bucket_start=b.bucket_start
	   AND mr.bucket_minutes=(EXTRACT(EPOCH FROM (b.bucket_end-b.bucket_start))/60)::integer LIMIT 1) mr ON TRUE
), current_shared_facts AS (
	SELECT f.*, f.bucket_start+INTERVAL '1 minute' AS bucket_end FROM key_ip_audit_ip_1m sh
	JOIN security_activity_1m f ON f.api_key_id=sh.api_key_id AND f.client_ip=sh.client_ip
	 AND f.bucket_start=sh.bucket_start
	JOIN candidate_keys k ON k.key_id=f.api_key_id
	WHERE sh.shared_ip AND sh.bucket_start >= $1
	  AND sh.bucket_start + INTERVAL '1 minute' <= $2
	UNION ALL
	SELECT f.* FROM edge_shared es
	JOIN current_facts f ON f.api_key_id=es.api_key_id AND f.client_ip=es.client_ip
	 AND f.bucket_start=es.bucket_start
), shared_ip_stats AS (
	SELECT api_key_id, client_ip,
	       BOOL_OR(` + keyIPAuditFactEffective("f", "shared_ip_cross_users", "$1", "$2") + `) AS has_effective_activity
	FROM current_shared_facts f GROUP BY api_key_id, client_ip
), current_ip_ranked AS (
	SELECT i.*, COALESCE(s.is_baseline, FALSE) AS is_baseline,
	       ROW_NUMBER() OVER (PARTITION BY i.api_key_id ORDER BY i.first_seen, i.client_ip) AS ip_rank,
	       COALESCE(s.first_seen, i.first_seen) AS observed_first_seen,
	       EXISTS (
		SELECT 1 FROM key_ip_audit_trusted_ips t
		WHERE t.api_key_id = i.api_key_id
		  AND (t.expires_at IS NULL OR t.expires_at > NOW())
		  AND try_inet(NULLIF(BTRIM(i.client_ip), '')) <<= t.cidr::inet
	       ) AS trusted,
	       (sh.client_ip IS NOT NULL) AS raw_shared,
	       EXISTS (
		SELECT 1 FROM current_facts f
		WHERE f.api_key_id = i.api_key_id AND f.client_ip = i.client_ip
		  AND ` + keyIPAuditFactEffective("f", "new_ip", "$1", "$2") + `
	       ) AS has_effective_new_activity,
	       COALESCE(sh.has_effective_activity, FALSE) AS has_effective_shared_activity
	FROM current_ip_stats i
	LEFT JOIN key_ip_audit_ip_state s ON s.api_key_id = i.api_key_id AND s.client_ip = i.client_ip
	LEFT JOIN shared_ip_stats sh ON sh.api_key_id=i.api_key_id AND sh.client_ip=i.client_ip
), ip_counts AS (
	SELECT api_key_id,
	       COUNT(*)::bigint AS ip_count,
	       COUNT(*) FILTER (WHERE NOT is_baseline AND observed_first_seen >= $1)::bigint AS raw_new_ip_count,
	       COUNT(*) FILTER (WHERE NOT is_baseline AND observed_first_seen >= $1 AND NOT trusted AND has_effective_new_activity)::bigint AS new_ip_count,
	       COUNT(*) FILTER (WHERE raw_shared)::bigint AS raw_shared_ip_count,
	       COUNT(*) FILTER (WHERE raw_shared AND has_effective_shared_activity)::bigint AS shared_ip_count,
	       ARRAY_AGG(client_ip) FILTER (WHERE raw_shared AND has_effective_shared_activity) AS shared_ips,
	       BOOL_OR(NOT is_baseline AND observed_first_seen >= $1 AND NOT trusted AND NOT has_effective_new_activity) AS new_ip_dismissed,
	       BOOL_OR(raw_shared AND NOT has_effective_shared_activity) AS shared_ip_dismissed
	FROM current_ip_ranked GROUP BY api_key_id
), raw_rapid AS (
	SELECT api_key_id, COALESCE(MAX(raw_rapid_ip_count), 0)::bigint AS raw_rapid_ip_count
	FROM raw_rapid_buckets
	GROUP BY api_key_id
), burst_dismissed_keys AS (
	SELECT DISTINCT c.api_key_id FROM current_key_stats c
	JOIN key_ip_audit_dismissals d ON d.api_key_id=c.api_key_id
	WHERE d.risk_code='multi_ip_burst' AND d.event_start < $2
	  AND d.event_end > $1::timestamptz-INTERVAL '10 minutes'
), dismissal_affected_fact_buckets AS (
	SELECT DISTINCT b.api_key_id, b.bucket_start, b.bucket_end
	FROM current_buckets b
	JOIN key_ip_audit_dismissals d
	  ON d.api_key_id=b.api_key_id AND d.risk_code='multi_ip_burst'
	 AND d.event_start < b.bucket_end
	 AND d.event_end > b.bucket_start-INTERVAL '10 minutes'
), dismissal_current_buckets AS (
	SELECT DISTINCT m.api_key_id, m.bucket_start FROM key_ip_audit_key_1m m
	JOIN dismissal_affected_fact_buckets b ON b.api_key_id=m.api_key_id
	 AND m.bucket_start>=b.bucket_start AND m.bucket_start<b.bucket_end
	WHERE m.bucket_start < $2 AND m.bucket_start+INTERVAL '1 minute' > $1
), dismissal_raw_rapid_buckets AS (
	SELECT b.api_key_id, b.bucket_start,
	       CASE WHEN eb.bucket_start IS NOT NULL THEN COALESCE(er.rapid_ip_count,0)
	            ELSE m.raw_rapid_ip_count END::bigint AS raw_rapid_ip_count
	FROM dismissal_current_buckets b
	JOIN key_ip_audit_key_1m m ON m.api_key_id=b.api_key_id AND m.bucket_start=b.bucket_start
	LEFT JOIN edge_buckets eb ON eb.api_key_id=b.api_key_id AND eb.bucket_start=b.bucket_start
	LEFT JOIN edge_rapid er ON er.api_key_id=b.api_key_id AND er.bucket_start=b.bucket_start
), effective_rapid_counts AS (
	SELECT b.api_key_id, b.bucket_start, anchor.created_at,
	       COUNT(DISTINCT context_event.client_ip)::bigint AS rapid_ip_count
	FROM dismissal_current_buckets b
	JOIN key_ip_audit_dismissals d
	  ON d.api_key_id=b.api_key_id AND d.risk_code='multi_ip_burst'
	 AND d.event_start < b.bucket_start + INTERVAL '1 minute'
	 AND d.event_end > b.bucket_start - INTERVAL '10 minutes'
	JOIN security_activity_events anchor
	  ON anchor.api_key_id=b.api_key_id
	 AND anchor.created_at >= GREATEST(b.bucket_start, $1::timestamptz)
	 AND anchor.created_at < LEAST(b.bucket_start + INTERVAL '1 minute', $2::timestamptz)
	JOIN security_activity_events context_event
	  ON context_event.api_key_id=anchor.api_key_id AND context_event.client_ip<>''
	 AND context_event.created_at >= anchor.created_at - INTERVAL '10 minutes'
	 AND context_event.created_at <= anchor.created_at
	 AND NOT EXISTS (
		SELECT 1 FROM key_ip_audit_dismissals suppressed
		WHERE suppressed.api_key_id=context_event.api_key_id
		  AND suppressed.risk_code='multi_ip_burst'
		  AND host(try_inet(NULLIF(BTRIM(suppressed.ip_address),'')))=context_event.client_ip
		  AND suppressed.event_start<=context_event.created_at
		  AND suppressed.event_end>context_event.created_at)
	GROUP BY b.api_key_id, b.bucket_start, anchor.created_at
), effective_rapid_buckets AS (
	SELECT r.api_key_id, r.bucket_start, MAX(r.rapid_ip_count)::bigint AS rapid_ip_count
	FROM effective_rapid_counts r GROUP BY r.api_key_id, r.bucket_start
), dismissal_unaffected_raw_rapid AS (
	SELECT r.api_key_id, MAX(r.raw_rapid_ip_count)::bigint AS rapid_ip_count
	FROM raw_rapid_buckets r
	JOIN burst_dismissed_keys k ON k.api_key_id=r.api_key_id
	LEFT JOIN dismissal_affected_fact_buckets a
	  ON a.api_key_id=r.api_key_id AND a.bucket_start=r.bucket_start
	WHERE a.api_key_id IS NULL
	GROUP BY r.api_key_id
), dismissal_affected_effective_rapid AS (
	SELECT b.api_key_id, COALESCE(MAX(CASE WHEN eb.bucket_start IS NOT NULL
		THEN COALESCE(er.rapid_ip_count, 0) ELSE b.raw_rapid_ip_count END), 0)::bigint AS rapid_ip_count
	FROM dismissal_raw_rapid_buckets b
	LEFT JOIN (SELECT DISTINCT cb.api_key_id, cb.bucket_start FROM key_ip_audit_dismissals d
			   JOIN dismissal_current_buckets cb ON cb.api_key_id=d.api_key_id
			   WHERE d.risk_code='multi_ip_burst'
				     AND d.event_start < cb.bucket_start + INTERVAL '1 minute'
				     AND d.event_end > cb.bucket_start - INTERVAL '10 minutes') eb
	  ON eb.api_key_id=b.api_key_id AND eb.bucket_start=b.bucket_start
	LEFT JOIN effective_rapid_buckets er ON er.api_key_id=b.api_key_id AND er.bucket_start=b.bucket_start
	GROUP BY b.api_key_id
), dismissed_effective_rapid AS (
	SELECT k.api_key_id,
	       GREATEST(COALESCE(u.rapid_ip_count,0),COALESCE(a.rapid_ip_count,0))::bigint AS rapid_ip_count
	FROM burst_dismissed_keys k
	LEFT JOIN dismissal_unaffected_raw_rapid u ON u.api_key_id=k.api_key_id
	LEFT JOIN dismissal_affected_effective_rapid a ON a.api_key_id=k.api_key_id
), effective_rapid AS (
	SELECT r.api_key_id, COALESCE(d.rapid_ip_count,r.raw_rapid_ip_count)::bigint AS rapid_ip_count
	FROM raw_rapid r LEFT JOIN dismissed_effective_rapid d ON d.api_key_id=r.api_key_id
), effective_volume AS (
	SELECT api_key_id,
	       SUM(` + keyIPAuditEffectiveCount("current_facts", "$1", "$2") + `)::bigint AS effective_current_request_count
	FROM current_facts GROUP BY api_key_id
), effective_prior_volume AS (
	SELECT api_key_id,
	       SUM(` + keyIPAuditEffectiveCount("prior_facts", "$3", "$1") + `)::bigint AS effective_prior_request_count
	FROM prior_facts GROUP BY api_key_id
), volume_flags AS (
	SELECT c.api_key_id,
	       COALESCE(p.request_count, 0)::bigint AS prior_request_count,
	       COALESCE(e.effective_current_request_count, 0)::bigint AS effective_current_request_count,
	       COALESCE(ep.effective_prior_request_count, 0)::bigint AS effective_prior_request_count,
	       (c.request_count >= 20 AND ((COALESCE(p.request_count, 0) = 0 AND c.request_count >= 50)
		OR (COALESCE(p.request_count, 0) > 0 AND c.request_count >= p.request_count * 3 AND c.request_count - p.request_count >= 20))
		AND (COALESCE(p.request_count, 0) > 0 OR COALESCE(ic.raw_new_ip_count, 0) > 0 OR COALESCE(rr.raw_rapid_ip_count, 0) >= 3)) AS raw_volume_spike,
	       (COALESCE(e.effective_current_request_count, 0) >= 20 AND ((COALESCE(ep.effective_prior_request_count, 0) = 0 AND COALESCE(e.effective_current_request_count, 0) >= 50)
		OR (COALESCE(ep.effective_prior_request_count, 0) > 0 AND COALESCE(e.effective_current_request_count, 0) >= ep.effective_prior_request_count * 3 AND COALESCE(e.effective_current_request_count, 0) - ep.effective_prior_request_count >= 20))
		AND (COALESCE(ep.effective_prior_request_count, 0) > 0 OR COALESCE(ic.new_ip_count, 0) > 0 OR COALESCE(er.rapid_ip_count, 0) >= 3)) AS volume_spike,
	       (COALESCE(e.effective_current_request_count, 0) < c.request_count
		OR COALESCE(ep.effective_prior_request_count, 0) < COALESCE(p.request_count, 0)) AS volume_dismissed
	FROM current_key_stats c
	LEFT JOIN prior_key_stats p ON p.api_key_id = c.api_key_id
	LEFT JOIN effective_volume e ON e.api_key_id = c.api_key_id
	LEFT JOIN effective_prior_volume ep ON ep.api_key_id = c.api_key_id
	LEFT JOIN ip_counts ic ON ic.api_key_id = c.api_key_id
	LEFT JOIN raw_rapid rr ON rr.api_key_id = c.api_key_id
	LEFT JOIN effective_rapid er ON er.api_key_id = c.api_key_id
), latest_ip AS (
	SELECT DISTINCT ON (api_key_id) api_key_id, client_ip
	FROM current_ip_stats ORDER BY api_key_id, last_seen DESC, client_ip
), key_rows AS (
	SELECT k.key_id, k.key_name, k.key_prefix, k.key_status, k.owner_user_id AS user_id, k.user_email,
	       li.client_ip AS latest_ip, COALESCE(ic.ip_count, 0)::bigint AS ip_count,
	       COALESCE(ic.raw_new_ip_count, 0)::bigint AS raw_new_ip_count,
	       COALESCE(ic.new_ip_count, 0)::bigint AS new_ip_count,
	       c.first_seen, c.last_seen, c.request_count,
	       COALESCE(v.prior_request_count, 0)::bigint AS prior_request_count,
	       COALESCE(rr.raw_rapid_ip_count, 0)::bigint AS raw_rapid_ip_count,
	       COALESCE(er.rapid_ip_count, 0)::bigint AS rapid_ip_count,
	       COALESCE(ic.raw_shared_ip_count, 0)::bigint AS raw_shared_ip_count,
	       COALESCE(ic.shared_ip_count, 0)::bigint AS shared_ip_count,
	       COALESCE(ic.shared_ips, ARRAY[]::text[]) AS shared_ips,
	       COALESCE(v.raw_volume_spike, FALSE) AS raw_volume_spike,
	       COALESCE(v.volume_spike, FALSE) AS volume_spike,
	       COALESCE(v.effective_current_request_count, 0)::bigint AS effective_current_request_count,
	       COALESCE(v.effective_prior_request_count, 0)::bigint AS effective_prior_request_count,
	       (COALESCE(ic.new_ip_dismissed, FALSE)
		OR COALESCE(ic.shared_ip_dismissed, FALSE)
		OR COALESCE(rr.raw_rapid_ip_count, 0) >= 3 AND COALESCE(er.rapid_ip_count, 0) < 3
		OR COALESCE(v.raw_volume_spike, FALSE) AND NOT COALESCE(v.volume_spike, FALSE) AND COALESCE(v.volume_dismissed, FALSE)) AS has_dismissal,
	       EXISTS (SELECT 1 FROM current_ip_stats ci WHERE ci.api_key_id = k.key_id AND ($8 = '' OR ci.client_ip = $8)) AS has_requested_ip
	FROM candidate_keys k
	JOIN current_key_stats c ON c.api_key_id = k.key_id
	LEFT JOIN latest_ip li ON li.api_key_id = k.key_id
	LEFT JOIN ip_counts ic ON ic.api_key_id = k.key_id
	LEFT JOIN volume_flags v ON v.api_key_id = k.key_id
	LEFT JOIN raw_rapid rr ON rr.api_key_id = k.key_id
	LEFT JOIN effective_rapid er ON er.api_key_id = k.key_id
), risk_scored AS (
	SELECT r.*,
	       CASE WHEN r.rapid_ip_count >= 3 OR (r.new_ip_count > 0 AND r.volume_spike) THEN 'high'
		WHEN r.new_ip_count > 0 OR r.shared_ip_count > 0 OR r.volume_spike THEN 'medium'
		ELSE 'none' END AS risk_level,
	       CASE WHEN r.raw_rapid_ip_count >= 3 OR r.raw_new_ip_count > 0 OR r.raw_shared_ip_count > 0 OR r.raw_volume_spike THEN TRUE ELSE FALSE END AS raw_risk
	FROM key_rows r
)
SELECT *,
       CASE WHEN risk_level <> 'none' THEN 'open' WHEN raw_risk AND has_dismissal THEN 'dismissed' ELSE 'normal' END AS audit_status
FROM risk_scored`

var (
	keyIPAuditPriorFacts = keyIPAuditWindowFacts("$3", "$1", "candidate_keys")
)

// Pick disjoint complete buckets at the coarsest available resolution. Only
// clipped minute edges use events, preserving exact [from,to) request counts.
func keyIPAuditWindowFacts(start, end, keys string) string {
	return keyIPAuditWindowFactsWithMaxBucket(start, end, keys, 1440)
}

func keyIPAuditWindowFactsWithMaxBucket(start, end, keys string, maxMinutes int) string {
	return fmt.Sprintf(`
		WITH window_keys AS (SELECT key_id FROM %[3]s k), floors AS (
			SELECT %[1]s::timestamptz AS from_at, %[2]s::timestamptz AS to_at,
			       date_trunc('minute', %[1]s::timestamptz) AS minute_floor,
			       date_trunc('minute', %[2]s::timestamptz) AS minute_to,
			       date_trunc('hour', %[1]s::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour_floor,
			       date_trunc('hour', %[2]s::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS hour_to,
			       date_trunc('day', %[1]s::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS day_floor,
			       date_trunc('day', %[2]s::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS day_to
		), bounds AS (
			SELECT *, minute_floor + CASE WHEN from_at=minute_floor THEN INTERVAL '0' ELSE INTERVAL '1 minute' END AS minute_from,
			       hour_floor + CASE WHEN from_at=hour_floor THEN INTERVAL '0' ELSE INTERVAL '60 minutes' END AS hour_from,
			       day_floor + CASE WHEN from_at=day_floor THEN INTERVAL '0' ELSE INTERVAL '1440 minutes' END AS day_from
			FROM floors
		)
		SELECT a.bucket_start, a.api_key_id, a.user_id, a.client_ip, a.user_agent,
		       a.request_count, a.missing_ip_count, a.missing_user_agent_count, a.first_seen, a.last_seen,
		       a.bucket_start + make_interval(mins => a.bucket_minutes) AS bucket_end
		FROM security_activity_rollups a JOIN window_keys k ON k.key_id=a.api_key_id CROSS JOIN bounds b
		WHERE (a.bucket_minutes=1440 AND %[4]d>=1440 AND a.bucket_start>=b.day_from AND a.bucket_start<b.day_to)
		   OR (a.bucket_minutes=60 AND a.bucket_start>=b.hour_from
		       AND a.bucket_start<CASE WHEN %[4]d<1440 OR b.day_from>=b.day_to THEN b.hour_to ELSE LEAST(b.day_from,b.hour_to) END)
		   OR (a.bucket_minutes=60 AND %[4]d>=1440 AND b.day_from<b.day_to
		       AND a.bucket_start>=GREATEST(b.day_to,b.hour_from) AND a.bucket_start<b.hour_to)
		UNION ALL
		SELECT a.*, a.bucket_start+INTERVAL '1 minute' AS bucket_end
		FROM security_activity_1m a JOIN window_keys k ON k.key_id=a.api_key_id CROSS JOIN bounds b
		WHERE (a.bucket_start>=b.minute_from
		       AND a.bucket_start<CASE WHEN b.hour_from>=b.hour_to THEN b.minute_to ELSE LEAST(b.hour_from,b.minute_to) END)
		   OR (b.hour_from<b.hour_to AND a.bucket_start>=GREATEST(b.hour_to,b.minute_from) AND a.bucket_start<b.minute_to)
		UNION ALL
		SELECT date_trunc('minute', e.created_at), e.api_key_id, e.user_id,
		       e.client_ip, e.user_agent, COUNT(*)::bigint,
		       COUNT(*) FILTER (WHERE e.client_ip='')::bigint,
		       COUNT(*) FILTER (WHERE e.user_agent='')::bigint,
		       MIN(e.created_at), MAX(e.created_at), date_trunc('minute', e.created_at)+INTERVAL '1 minute'
		FROM security_activity_events e JOIN window_keys k ON k.key_id=e.api_key_id CROSS JOIN bounds b
		WHERE e.created_at>=b.from_at AND e.created_at<b.to_at
		  AND ((b.from_at>b.minute_floor AND e.created_at<b.minute_floor+INTERVAL '1 minute')
		    OR (b.to_at>b.minute_to AND e.created_at>=b.minute_to))
		GROUP BY 1,2,3,4,5,11`, start, end, keys, maxMinutes)
}

// A partial-minute dismissal must be checked against event times, not merely
// the min/max of a fact; the fast path leaves ordinary facts on the rollup.
func keyIPAuditFactEffective(fact, risk, start, end string) string {
	dismissal := fmt.Sprintf(`d.api_key_id=%[1]s.api_key_id AND d.risk_code='%[2]s'
		AND %[1]s.client_ip<>''
		AND host(try_inet(NULLIF(BTRIM(d.ip_address), '')))=%[1]s.client_ip`, fact, risk)
	eventDismissal := fmt.Sprintf(`d.api_key_id=e.api_key_id AND d.risk_code='%s'
		AND host(try_inet(NULLIF(BTRIM(d.ip_address), '')))=e.client_ip
		AND d.event_start<=e.created_at AND d.event_end>e.created_at`, risk)
	return fmt.Sprintf(`(NOT EXISTS (SELECT 1 FROM key_ip_audit_dismissals d WHERE %s
		AND d.event_start<=%s.last_seen AND d.event_end>%s.first_seen)
		OR EXISTS (SELECT 1 FROM security_activity_events e
			WHERE e.api_key_id=%s.api_key_id AND e.user_id=%s.user_id
			  AND e.client_ip=%s.client_ip AND e.user_agent=%s.user_agent
			  AND e.created_at>=GREATEST(%s.bucket_start,%s)
			  AND e.created_at<LEAST(%s.bucket_end,%s)
			  AND NOT EXISTS (SELECT 1 FROM key_ip_audit_dismissals d WHERE %s)))`,
		dismissal, fact, fact, fact, fact, fact, fact, fact, start, fact, end, eventDismissal)
}

func keyIPAuditEffectiveCount(fact, start, end string) string {
	overlaps := fmt.Sprintf(`d.api_key_id=%[1]s.api_key_id AND d.risk_code='volume_spike'
		AND host(try_inet(NULLIF(BTRIM(d.ip_address), '')))=%[1]s.client_ip
		AND d.event_start<=%[1]s.last_seen AND d.event_end>%[1]s.first_seen`, fact)
	return fmt.Sprintf(`CASE WHEN %s.client_ip='' OR NOT EXISTS (
		SELECT 1 FROM key_ip_audit_dismissals d WHERE %s) THEN %s.request_count
		ELSE (SELECT COUNT(*) FROM security_activity_events e
			WHERE e.api_key_id=%s.api_key_id AND e.user_id=%s.user_id
			  AND e.client_ip=%s.client_ip AND e.user_agent=%s.user_agent
			  AND e.created_at>=GREATEST(%s.bucket_start,%s)
			  AND e.created_at<LEAST(%s.bucket_end,%s)
			  AND NOT EXISTS (SELECT 1 FROM key_ip_audit_dismissals d
			    WHERE d.api_key_id=e.api_key_id AND d.risk_code='volume_spike'
			      AND host(try_inet(NULLIF(BTRIM(d.ip_address), '')))=e.client_ip
			      AND d.event_start<=e.created_at AND d.event_end>e.created_at)) END`,
		fact, overlaps, fact, fact, fact, fact, fact, fact, start, fact, end)
}

func (r *keyIPAuditRepository) listKeysMaterialized(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, excludeKeyID int64) (*service.KeyIPAuditKeyList, error) {
	args := keyIPAuditArgs(filter)
	if err := createKeyIPAuditScoredTemp(ctx, q, args); err != nil {
		return nil, err
	}
	where := keyIPAuditMaterializedWhere("s")
	// The status placeholder is consumed in candidate_keys; keep the final
	// predicate parameter positions explicit because the public filter accepts
	// both key status and audit risk status.
	argsWithExclude := append(append([]any{}, args...), excludeKeyID)
	var total int64
	if err := scanSingleRow(ctx, q, `SELECT COUNT(*) FROM key_ip_audit_scored s `+where, argsWithExclude, &total); err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `
		SELECT key_id, key_name, key_prefix, key_status, user_id, user_email, latest_ip,
		       ip_count, new_ip_count, first_seen, last_seen, request_count, prior_request_count,
		       raw_new_ip_count, raw_rapid_ip_count, rapid_ip_count, raw_shared_ip_count,
		       shared_ip_count, raw_volume_spike, volume_spike, effective_current_request_count,
		       effective_prior_request_count, has_dismissal
		FROM key_ip_audit_scored s `+where+`
		ORDER BY CASE s.risk_level WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END DESC,
		         s.last_seen DESC, s.key_id ASC LIMIT $13 OFFSET $14`,
		append(append([]any{}, argsWithExclude...), filter.PageSize, (filter.Page-1)*filter.PageSize)...)
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
	summary, err := queryMaterializedKeySummary(ctx, q, argsWithExclude)
	if err != nil {
		return nil, err
	}
	coverage, err := queryMaterializedCoverage(ctx, q, filter, argsWithExclude)
	if err != nil {
		return nil, err
	}
	trend, err := queryMaterializedTrend(ctx, q, argsWithExclude, filter)
	if err != nil {
		return nil, err
	}
	return &service.KeyIPAuditKeyList{Items: items, Total: total, Page: filter.Page, PageSize: filter.PageSize,
		Summary: *summary, Trend: trend, Metadata: service.KeyIPAuditMetadata{From: filter.StartTime, To: filter.EndTime, Coverage: *coverage}}, nil
}

func createKeyIPAuditScoredTemp(ctx context.Context, q sqlQueryer, args []any) error {
	execQ, ok := q.(interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	})
	if !ok {
		return fmt.Errorf("key/ip audit queryer does not support projection temp tables")
	}
	if _, err := execQ.ExecContext(ctx, `DROP TABLE IF EXISTS key_ip_audit_scored`); err != nil {
		return err
	}
	if _, err := execQ.ExecContext(ctx, `DROP TABLE IF EXISTS key_ip_audit_current_facts`); err != nil {
		return err
	}
	// This relation is reused by per-key/IP risk, dismissal and volume checks.
	// Indexing it avoids rescanning the entire time window for each distinct IP.
	if _, err := execQ.ExecContext(ctx, `CREATE TEMP TABLE key_ip_audit_current_facts ON COMMIT DROP AS `+
		keyIPAuditWindowFacts("$1", "$2", "("+keyIPAuditCandidateKeys+")"), args...); err != nil {
		return err
	}
	if _, err := execQ.ExecContext(ctx, `CREATE INDEX ON key_ip_audit_current_facts (api_key_id, client_ip, bucket_start)`); err != nil {
		return err
	}
	if _, err := execQ.ExecContext(ctx, `ANALYZE key_ip_audit_current_facts`); err != nil {
		return err
	}
	_, err := execQ.ExecContext(ctx, `CREATE TEMP TABLE key_ip_audit_scored ON COMMIT DROP AS `+keyIPAuditMaterializedCTE, args...)
	return err
}

func keyIPAuditMaterializedWhere(alias string) string {
	return fmt.Sprintf(`WHERE ($1::timestamptz IS NULL OR $1::timestamptz IS NOT NULL)
	  AND ($2::timestamptz IS NULL OR $2::timestamptz IS NOT NULL)
	  AND ($3::timestamptz IS NULL OR $3::timestamptz IS NOT NULL)
	  AND ($4::bigint IS NULL OR $4::bigint IS NOT NULL)
	  AND ($5::bigint IS NULL OR $5::bigint IS NOT NULL)
	  AND ($6::text IS NULL OR $6::text IS NOT NULL)
	  AND ($7::text IS NULL OR $7::text IS NOT NULL)
	  AND ($8::text IS NULL OR $8::text IS NOT NULL)
	  AND ($8::text = '' OR %[1]s.has_requested_ip) AND ($9::text = '' OR $9::text = 'all' OR %[1]s.risk_level = $9::text)
	  AND ($10::text IS NULL OR $10::text IS NOT NULL)
	  AND ($11::text = '' OR $11::text = 'all' OR ($11::text = 'new_ip' AND %[1]s.new_ip_count > 0)
	       OR ($11::text = 'multi_ip_burst' AND %[1]s.rapid_ip_count >= 3)
	       OR ($11::text = 'shared_ip_cross_users' AND %[1]s.shared_ip_count > 0)
	       OR ($11::text = 'volume_spike' AND %[1]s.volume_spike))
	  AND ($12::bigint = 0 OR %[1]s.key_id <> $12::bigint)`, alias)
}

func queryMaterializedKeySummary(ctx context.Context, q sqlQueryer, args []any) (*service.KeyIPAuditKeySummary, error) {
	var s service.KeyIPAuditKeySummary
	where := keyIPAuditMaterializedWhere("s")
	sharedWhere := keyIPAuditMaterializedWhere("x")
	if err := scanSingleRow(ctx, q, `SELECT COUNT(*)::bigint, COUNT(*) FILTER (WHERE risk_level='high')::bigint,
		COUNT(*) FILTER (WHERE new_ip_count > 0)::bigint, COUNT(*) FILTER (WHERE rapid_ip_count >= 3)::bigint,
		(SELECT COUNT(DISTINCT ip.client_ip)::bigint FROM key_ip_audit_scored x
		 CROSS JOIN LATERAL unnest(x.shared_ips) AS ip(client_ip)
		 WHERE ($8 = '' OR ip.client_ip = $8)
		   AND `+strings.TrimPrefix(sharedWhere, "WHERE ")+`),
		COUNT(*) FILTER (WHERE audit_status='open')::bigint
		FROM key_ip_audit_scored s `+where, args, &s.TotalKeys, &s.HighRiskKeys, &s.NewIPKeys, &s.MultiIPKeys, &s.SharedIPs, &s.PendingKeys); err != nil {
		return nil, err
	}
	return &s, nil
}

func queryMaterializedCoverage(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, args []any) (*service.KeyIPAuditCoverage, error) {
	var c service.KeyIPAuditCoverage
	var liveSince, dataThrough, pendingSince sql.NullTime
	where := keyIPAuditMaterializedWhere("s")
	if err := scanSingleRow(ctx, q, `WITH candidate_keys AS (
		`+keyIPAuditCandidateKeys+`
	), fact_stats AS (
		SELECT COALESCE(SUM(f.request_count),0)::bigint AS request_count,
		       COALESCE(SUM(f.missing_ip_count),0)::bigint AS missing_ip_count,
		       COALESCE(SUM(f.missing_user_agent_count),0)::bigint AS missing_user_agent_count
		FROM key_ip_audit_current_facts f
		JOIN key_ip_audit_scored s ON s.key_id=f.api_key_id
		WHERE ($8 = '' OR f.client_ip = $8)
		  AND `+strings.TrimPrefix(where, "WHERE ")+`
	)
	SELECT f.request_count, f.missing_ip_count, f.missing_user_agent_count,
	       p.live_since, p.data_through,
	       (SELECT MIN(q.created_at) FROM security_activity_projection_queue q
	        WHERE q.enqueued_at >= p.live_since
	          AND q.created_at < $2::timestamptz
	          AND (p.data_through IS NULL OR q.created_at < p.data_through)
	          AND (
	            EXISTS (
	              SELECT 1 FROM candidate_keys k
	              WHERE k.key_id = q.api_key_id
	                AND ($12::bigint = 0 OR k.key_id <> $12::bigint)
	            )
	            OR (
	              try_inet(NULLIF(BTRIM(q.ip_address), '')) IS NOT NULL AND q.user_id <> 0
	              AND EXISTS (
	                SELECT 1
	                FROM security_activity_events e
	                JOIN candidate_keys k ON k.key_id = e.api_key_id
	                WHERE e.client_ip = host(try_inet(NULLIF(BTRIM(q.ip_address), '')))
	                  AND e.api_key_id <> q.api_key_id
	                  AND e.user_id <> 0 AND e.user_id <> q.user_id
	                  AND e.created_at >= $1::timestamptz
	                  AND e.created_at < $2::timestamptz
	                  AND q.created_at >= e.created_at - INTERVAL '10 minutes'
	                  AND q.created_at < date_trunc('minute', e.created_at) + INTERVAL '1 minute'
	                  AND ($12::bigint = 0 OR e.api_key_id <> $12::bigint)
	              )
	            )
	          ))
	FROM key_ip_audit_projection_state p CROSS JOIN fact_stats f
	WHERE p.id=1`, args, &c.UsageLogCount, &c.MissingIPCount, &c.MissingUserAgentCount, &liveSince, &dataThrough, &pendingSince); err != nil {
		return nil, err
	}
	c.Source = "security_activity_projection"
	if liveSince.Valid {
		c.LiveSince = liveSince.Time.UTC()
	}
	if pendingSince.Valid && dataThrough.Valid && pendingSince.Time.Before(dataThrough.Time) {
		dataThrough.Time = pendingSince.Time
	}
	if dataThrough.Valid {
		c.DataThrough = dataThrough.Time.UTC()
		if lag := time.Since(c.DataThrough).Seconds(); lag > 0 {
			c.AggregationLagSeconds = int64(lag)
		}
	}
	retainedSince := time.Now().UTC().Add(-keyIPAuditProjectionRetention)
	availableSince := c.LiveSince
	if retainedSince.After(availableSince) {
		availableSince = retainedSince
	}
	c.Reason = "complete"
	if !liveSince.Valid || filter.StartTime.Before(availableSince) {
		c.Reason = "history_unavailable"
	} else if !dataThrough.Valid || pendingSince.Valid || filter.EndTime.After(c.DataThrough) {
		c.Reason = "projection_pending"
	}
	c.CoverageComplete = c.Reason == "complete"
	contextCoverage := c
	contextCoverage.LiveSince = availableSince
	c.RiskContextComplete = service.KeyIPAuditRiskContextComplete(filter, contextCoverage)
	if c.UsageLogCount > 0 {
		c.IPCoveragePercent = float64(c.UsageLogCount-c.MissingIPCount) * 100 / float64(c.UsageLogCount)
	}
	return &c, nil
}

func queryMaterializedTrend(ctx context.Context, q sqlQueryer, args []any, filter service.KeyIPAuditFilter) ([]service.KeyIPAuditTrendPoint, error) {
	bucket := "hour"
	if filter.EndTime.Sub(filter.StartTime) > 48*time.Hour {
		bucket = "day"
	}
	where := keyIPAuditMaterializedWhere("s")
	// Hour facts preserve trend buckets even when the count path uses UTC days.
	rows, err := q.QueryContext(ctx, fmt.Sprintf(`SELECT date_trunc('%s', f.bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', SUM(f.request_count)::bigint,
		COUNT(DISTINCT f.api_key_id) FILTER (WHERE s.risk_level <> 'none')::bigint
		FROM (`+keyIPAuditWindowFactsWithMaxBucket("$1", "$2", "key_ip_audit_scored", 60)+`) f
		JOIN key_ip_audit_scored s ON s.key_id=f.api_key_id
		WHERE ($8 = '' OR f.client_ip = $8)
		  AND %s
		GROUP BY 1 ORDER BY 1`, bucket, strings.TrimPrefix(where, "WHERE ")), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	trend := make([]service.KeyIPAuditTrendPoint, 0)
	for rows.Next() {
		var point service.KeyIPAuditTrendPoint
		if err := rows.Scan(&point.BucketStart, &point.RequestCount, &point.RiskyKeys); err != nil {
			return nil, err
		}
		trend = append(trend, point)
	}
	return trend, rows.Err()
}

func (r *keyIPAuditRepository) queryKeyIPAuditIPsMaterialized(ctx context.Context, q sqlQueryer, filter service.KeyIPAuditFilter, page, pageSize int) ([]service.KeyIPAuditIPRow, int64, error) {
	var total int64
	base := `WITH stats AS (
		SELECT f.client_ip AS ip, MIN(f.first_seen) AS first_seen, MAX(f.last_seen) AS last_seen,
		       SUM(f.request_count)::bigint AS request_count,
		       COUNT(DISTINCT NULLIF(f.user_agent,''))::bigint AS user_agent_count,
		       COALESCE(MIN(NULLIF(f.user_agent,'')), '') AS user_agent
		FROM (` + keyIPAuditWindowFacts("$1", "$2", "(SELECT $3::bigint AS key_id)") + `) f
		WHERE f.api_key_id = $3
		  AND f.client_ip <> ''
		GROUP BY f.client_ip
	), ranked AS (
		SELECT s.*, ROW_NUMBER() OVER (ORDER BY s.first_seen, s.ip) AS ip_rank,
		       COALESCE(st.is_baseline, FALSE) AS is_baseline,
		       COALESCE(st.first_seen, s.first_seen) AS observed_first_seen
		FROM stats s LEFT JOIN key_ip_audit_ip_state st ON st.api_key_id=$3 AND st.client_ip=s.ip
	), flags AS (
		SELECT r.*,
			EXISTS (SELECT 1 FROM key_ip_audit_trusted_ips t WHERE t.api_key_id=$3 AND (t.expires_at IS NULL OR t.expires_at>NOW()) AND try_inet(NULLIF(BTRIM(r.ip),'')) <<= t.cidr::inet) AS trusted,
			EXISTS (SELECT 1 FROM (` + keyIPAuditWindowFacts("$1", "$2", "(SELECT $3::bigint AS key_id)") + `) f
				WHERE f.api_key_id=$3 AND f.client_ip=r.ip
				AND ` + keyIPAuditFactEffective("f", "new_ip", "$1", "$2") + `) AS effective_new
		FROM ranked r
	)
	SELECT COUNT(*) FROM flags`
	if err := scanSingleRow(ctx, q, base, []any{filter.StartTime, filter.EndTime, filter.APIKeyID}, &total); err != nil {
		return nil, 0, err
	}
	rows, err := q.QueryContext(ctx, base[:strings.LastIndex(base, "SELECT COUNT(*)")]+`SELECT ip, first_seen, last_seen, request_count, user_agent, user_agent_count,
		CASE WHEN NOT is_baseline AND observed_first_seen >= $1 AND NOT trusted AND effective_new THEN TRUE ELSE FALSE END, trusted
		FROM flags ORDER BY last_seen DESC, ip ASC LIMIT $4 OFFSET $5`, filter.StartTime, filter.EndTime, filter.APIKeyID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]service.KeyIPAuditIPRow, 0, pageSize)
	for rows.Next() {
		var item service.KeyIPAuditIPRow
		if err := rows.Scan(&item.IP, &item.FirstSeen, &item.LastSeen, &item.RequestCount, &item.UserAgent, &item.UserAgentCount, &item.NewIP, &item.Trusted); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (r *keyIPAuditRepository) keyUsedIPMaterialized(ctx context.Context, q sqlQueryer, keyID int64, from, to time.Time, ip string) (bool, error) {
	var used bool
	err := scanSingleRow(ctx, q, `
		SELECT EXISTS (
			SELECT 1 FROM (`+keyIPAuditWindowFacts("$2", "$3", "(SELECT $1::bigint AS key_id)")+`) f
			WHERE f.api_key_id = $1 AND f.client_ip = $4
		)`, []any{keyID, from, to, ip}, &used)
	return used, err
}
