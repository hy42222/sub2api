//go:build integration

package repository

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

const (
	keyIPAuditPerfKeyCount       = 3894
	keyIPAuditPerfHoursPerWindow = 30 * 24
	keyIPAuditPerfNewIPEvery     = 10
	keyIPAuditPerfRapidEvery     = 100
	keyIPAuditPerfRapidCount     = 3
	keyIPAuditPerfSharedFirst    = 11
	keyIPAuditPerfSharedSecond   = 12
)

// Run explicitly with SUB2API_KEY_IP_AUDIT_PERF=1. Set
// SUB2API_KEY_IP_AUDIT_PERF_EXPLAIN=1 to also log isolated query plans. The disposable
// testcontainers database has 3894 keys, current/prior windows, and all
// production read-side rollups. Facts are hourly and UTC-noon aligned, so the
// reader exercises day/hour rollups without requiring an exact-event stream.
func TestKeyIPAuditPerformanceThirtyDays(t *testing.T) {
	if os.Getenv("SUB2API_KEY_IP_AUDIT_PERF") != "1" {
		t.Skip("set SUB2API_KEY_IP_AUDIT_PERF=1 for the 3894-key load check")
	}
	fixture := newKeyIPAuditFixture(t, "perf", "shared")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		_, err := integrationDB.ExecContext(cleanupCtx, `TRUNCATE TABLE
			security_activity_1m,
			security_activity_rollups,
			key_ip_audit_key_1m,
			key_ip_audit_key_rollups,
			key_ip_audit_ip_1m,
			key_ip_audit_key_state,
			key_ip_audit_ip_state`)
		if err != nil {
			t.Errorf("truncate perf fixture projections: %v", err)
			return
		}
		_, err = integrationDB.ExecContext(cleanupCtx,
			`DELETE FROM api_keys WHERE name LIKE $1`, fixture.prefix+"-perf-%")
		if err != nil {
			t.Errorf("delete perf fixture API keys: %v", err)
		}
	})

	insertedKeys, err := integrationDB.ExecContext(ctx, `
		INSERT INTO api_keys (user_id, key, name)
			SELECT CASE WHEN value = $5::bigint THEN $4::bigint ELSE $1::bigint END,
			       'sk-' || $2 || '-perf-' || value,
			       $2 || '-perf-' || value
			FROM generate_series(1, $3::bigint) AS value`,
		fixture.users[0].ID, fixture.prefix, keyIPAuditPerfKeyCount,
		fixture.users[1].ID, keyIPAuditPerfSharedSecond)
	require.NoError(t, err)
	keyRows, err := insertedKeys.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, keyIPAuditPerfKeyCount, keyRows)

	now := time.Now().UTC()
	currentTo := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)
	if currentTo.After(now) {
		currentTo = currentTo.Add(-24 * time.Hour)
	}
	currentFrom := currentTo.Add(-30 * 24 * time.Hour)
	priorFrom := currentFrom.Add(-30 * 24 * time.Hour)
	expectedFactRows := int64(keyIPAuditPerfKeyCount * 2 * keyIPAuditPerfHoursPerWindow)
	newIPKeyCount := int64(keyIPAuditPerfKeyCount / keyIPAuditPerfNewIPEvery)
	rapidKeyCount := int64(keyIPAuditPerfKeyCount / keyIPAuditPerfRapidEvery)
	dailyBucketCount := int64(keyIPAuditPerfUTCDateStart(currentTo).Sub(keyIPAuditPerfUTCDateStart(priorFrom))/(24*time.Hour)) + 1
	// Each new-IP key contributes one extra dimension on the UTC day that
	// contains the IP transition, not one extra row for every current-window day.
	expectedDailyActivityRows := int64(keyIPAuditPerfKeyCount)*dailyBucketCount + newIPKeyCount
	expectedDailyKeyRows := int64(keyIPAuditPerfKeyCount) * dailyBucketCount
	seedStart := time.Now()

	activityResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO security_activity_1m (
			bucket_start, api_key_id, user_id, client_ip, user_agent,
			request_count, missing_ip_count, missing_user_agent_count, first_seen, last_seen
		)
		SELECT b.bucket_start, k.id, k.user_id,
		       CASE WHEN b.bucket_start >= $4::timestamptz
		                  AND substring(k.name FROM length($1 || '-perf-') + 1)::bigint % $5 = 0
		            THEN '203.0.113.151' ELSE '203.0.113.150' END,
		       'perf-agent', 1, 0, 0,
		       b.bucket_start + INTERVAL '1 second', b.bucket_start + INTERVAL '1 second'
		FROM api_keys k
		CROSS JOIN LATERAL generate_series(
			$2::timestamptz, $3::timestamptz - INTERVAL '1 hour', INTERVAL '1 hour'
		) AS b(bucket_start)
		WHERE k.name LIKE $1 || '-perf-%'`,
		fixture.prefix, priorFrom, currentTo, currentFrom, keyIPAuditPerfNewIPEvery)
	require.NoError(t, err)
	activityRows, err := activityResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, expectedFactRows, activityRows)

	keyRollupResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO key_ip_audit_key_1m (
			bucket_start, api_key_id, first_seen, last_seen, request_count,
			missing_ip_count, missing_user_agent_count, raw_rapid_ip_count, raw_shared_ip_count
		)
		SELECT b.bucket_start, k.id,
		       b.bucket_start + INTERVAL '1 second', b.bucket_start + INTERVAL '1 second',
		       1, 0, 0,
		       CASE WHEN b.bucket_start = $4::timestamptz
		                  AND substring(k.name FROM length($1 || '-perf-') + 1)::bigint % $5 = 0
		            THEN $6::bigint ELSE 0 END,
		       CASE WHEN substring(k.name FROM length($1 || '-perf-') + 1)::bigint IN ($7, $8)
		            THEN 1 ELSE 0 END
		FROM api_keys k
		CROSS JOIN LATERAL generate_series(
			$2::timestamptz, $3::timestamptz - INTERVAL '1 hour', INTERVAL '1 hour'
		) AS b(bucket_start)
		WHERE k.name LIKE $1 || '-perf-%'`, fixture.prefix, priorFrom, currentTo,
		currentFrom, keyIPAuditPerfRapidEvery, keyIPAuditPerfRapidCount,
		keyIPAuditPerfSharedFirst, keyIPAuditPerfSharedSecond)
	require.NoError(t, err)
	keyRollupRows, err := keyRollupResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, expectedFactRows, keyRollupRows)

	ipRollupResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO key_ip_audit_ip_1m (
			bucket_start, api_key_id, client_ip, first_seen, last_seen,
			request_count, user_agent_count, user_agent, shared_ip
		)
		SELECT b.bucket_start, k.id,
		       CASE WHEN b.bucket_start >= $4::timestamptz
		                  AND substring(k.name FROM length($1 || '-perf-') + 1)::bigint % $5 = 0
		            THEN '203.0.113.151' ELSE '203.0.113.150' END,
		       b.bucket_start + INTERVAL '1 second', b.bucket_start + INTERVAL '1 second',
		       1, 1, 'perf-agent',
		       substring(k.name FROM length($1 || '-perf-') + 1)::bigint IN ($6, $7)
		FROM api_keys k
		CROSS JOIN LATERAL generate_series(
			$2::timestamptz, $3::timestamptz - INTERVAL '1 hour', INTERVAL '1 hour'
		) AS b(bucket_start)
		WHERE k.name LIKE $1 || '-perf-%'`,
		fixture.prefix, priorFrom, currentTo, currentFrom, keyIPAuditPerfNewIPEvery,
		keyIPAuditPerfSharedFirst, keyIPAuditPerfSharedSecond)
	require.NoError(t, err)
	ipRollupRows, err := ipRollupResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, expectedFactRows, ipRollupRows)
	var sharedMinuteRows int64
	err = integrationDB.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM key_ip_audit_ip_1m r
		JOIN api_keys k ON k.id = r.api_key_id
		WHERE k.name LIKE $1 || '-perf-%' AND r.shared_ip`,
		fixture.prefix).Scan(&sharedMinuteRows)
	require.NoError(t, err)
	require.Equal(t, int64(2*2*keyIPAuditPerfHoursPerWindow), sharedMinuteRows,
		"only the cross-owner pair should populate sparse shared-IP evidence")

	hourActivityRollupResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO security_activity_rollups (
			bucket_minutes, bucket_start, api_key_id, user_id, client_ip, user_agent,
			request_count, missing_ip_count, missing_user_agent_count, first_seen, last_seen
		)
		SELECT 60::smallint,
		       date_trunc('hour', a.bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
		       a.api_key_id, a.user_id, a.client_ip, a.user_agent,
		       a.request_count, a.missing_ip_count, a.missing_user_agent_count,
		       a.first_seen, a.last_seen
		FROM security_activity_1m a
		JOIN api_keys k ON k.id = a.api_key_id
		WHERE k.name LIKE $1 || '-perf-%'
		  AND a.bucket_start >= $2::timestamptz AND a.bucket_start < $3::timestamptz`,
		fixture.prefix, priorFrom, currentTo)
	require.NoError(t, err)
	hourActivityRollupRows, err := hourActivityRollupResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, expectedFactRows, hourActivityRollupRows)

	dailyActivityRollupResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO security_activity_rollups (
			bucket_minutes, bucket_start, api_key_id, user_id, client_ip, user_agent,
			request_count, missing_ip_count, missing_user_agent_count, first_seen, last_seen
		)
		SELECT 1440::smallint,
		       date_trunc('day', a.bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
		       a.api_key_id, a.user_id, a.client_ip, a.user_agent,
		       SUM(a.request_count)::bigint, SUM(a.missing_ip_count)::bigint,
		       SUM(a.missing_user_agent_count)::bigint,
		       MIN(a.first_seen), MAX(a.last_seen)
		FROM security_activity_1m a
		JOIN api_keys k ON k.id = a.api_key_id
		WHERE k.name LIKE $1 || '-perf-%'
		  AND a.bucket_start >= $2::timestamptz AND a.bucket_start < $3::timestamptz
		GROUP BY 2, 3, 4, 5, 6`,
		fixture.prefix, priorFrom, currentTo)
	require.NoError(t, err)
	dailyActivityRollupRows, err := dailyActivityRollupResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, expectedDailyActivityRows, dailyActivityRollupRows)

	var hourRequests, hourMissingIP, hourMissingAgent int64
	var dailyRequests, dailyMissingIP, dailyMissingAgent int64
	err = integrationDB.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(r.request_count) FILTER (WHERE r.bucket_minutes = 60), 0)::bigint,
			COALESCE(SUM(r.missing_ip_count) FILTER (WHERE r.bucket_minutes = 60), 0)::bigint,
			COALESCE(SUM(r.missing_user_agent_count) FILTER (WHERE r.bucket_minutes = 60), 0)::bigint,
			COALESCE(SUM(r.request_count) FILTER (WHERE r.bucket_minutes = 1440), 0)::bigint,
			COALESCE(SUM(r.missing_ip_count) FILTER (WHERE r.bucket_minutes = 1440), 0)::bigint,
			COALESCE(SUM(r.missing_user_agent_count) FILTER (WHERE r.bucket_minutes = 1440), 0)::bigint
		FROM security_activity_rollups r
		JOIN api_keys k ON k.id = r.api_key_id
		WHERE r.bucket_minutes IN (60, 1440) AND k.name LIKE $1 || '-perf-%'`,
		fixture.prefix).Scan(
		&hourRequests, &hourMissingIP, &hourMissingAgent,
		&dailyRequests, &dailyMissingIP, &dailyMissingAgent)
	require.NoError(t, err)
	require.Equal(t, expectedFactRows, hourRequests)
	require.Zero(t, hourMissingIP)
	require.Zero(t, hourMissingAgent)
	require.Equal(t, expectedFactRows, dailyRequests)
	require.Zero(t, dailyMissingIP)
	require.Zero(t, dailyMissingAgent)

	hourKeyRollupResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO key_ip_audit_key_rollups (
			bucket_minutes, bucket_start, api_key_id, raw_rapid_ip_count
		)
		SELECT 60::smallint,
		       date_trunc('hour', r.bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
		       r.api_key_id, MAX(r.raw_rapid_ip_count)::bigint
		FROM key_ip_audit_key_1m r
		JOIN api_keys k ON k.id = r.api_key_id
		WHERE k.name LIKE $1 || '-perf-%'
		  AND r.bucket_start >= $2::timestamptz AND r.bucket_start < $3::timestamptz
		GROUP BY 2, 3`, fixture.prefix, priorFrom, currentTo)
	require.NoError(t, err)
	hourKeyRollupRows, err := hourKeyRollupResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, expectedFactRows, hourKeyRollupRows)

	dailyKeyRollupResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO key_ip_audit_key_rollups (
			bucket_minutes, bucket_start, api_key_id, raw_rapid_ip_count
		)
		SELECT 1440::smallint,
		       date_trunc('day', r.bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
		       r.api_key_id, MAX(r.raw_rapid_ip_count)::bigint
		FROM key_ip_audit_key_1m r
		JOIN api_keys k ON k.id = r.api_key_id
		WHERE k.name LIKE $1 || '-perf-%'
		  AND r.bucket_start >= $2::timestamptz AND r.bucket_start < $3::timestamptz
		GROUP BY 2, 3`, fixture.prefix, priorFrom, currentTo)
	require.NoError(t, err)
	dailyKeyRollupRows, err := dailyKeyRollupResult.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, expectedDailyKeyRows, dailyKeyRollupRows)

	var hourlyRapidMarkers, dailyRapidMarkers int64
	err = integrationDB.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE r.bucket_minutes = 60
				AND r.bucket_start = $2::timestamptz AND r.raw_rapid_ip_count = $3),
			COUNT(*) FILTER (WHERE r.bucket_minutes = 1440
				AND r.bucket_start = $4::timestamptz AND r.raw_rapid_ip_count = $3)
		FROM key_ip_audit_key_rollups r
		JOIN api_keys k ON k.id = r.api_key_id
		WHERE k.name LIKE $1 || '-perf-%'
		  AND ((r.bucket_minutes = 60 AND r.bucket_start = $2::timestamptz)
		    OR (r.bucket_minutes = 1440 AND r.bucket_start = $4::timestamptz))`,
		fixture.prefix, currentFrom, keyIPAuditPerfRapidCount,
		keyIPAuditPerfUTCDateStart(currentFrom)).Scan(&hourlyRapidMarkers, &dailyRapidMarkers)
	require.NoError(t, err)
	require.Equal(t, rapidKeyCount, hourlyRapidMarkers)
	require.Equal(t, rapidKeyCount, dailyRapidMarkers)

	keyStateResult, err := integrationDB.ExecContext(ctx, `
		INSERT INTO key_ip_audit_key_state (
			api_key_id, first_seen, last_seen, latest_ip, request_count
		)
		SELECT k.id, $2::timestamptz + INTERVAL '1 second',
		       $3::timestamptz - INTERVAL '1 hour' + INTERVAL '1 second',
		       CASE WHEN substring(k.name FROM length($1 || '-perf-') + 1)::bigint % $5 = 0
		            THEN '203.0.113.151' ELSE '203.0.113.150' END, $4
		FROM api_keys k WHERE k.name LIKE $1 || '-perf-%'`,
		fixture.prefix, priorFrom, currentTo, 2*keyIPAuditPerfHoursPerWindow, keyIPAuditPerfNewIPEvery)
	require.NoError(t, err)
	keyStateRows, err := keyStateResult.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, keyIPAuditPerfKeyCount, keyStateRows)

	ipStateResult, err := integrationDB.ExecContext(ctx, `
		WITH perf_keys AS (
			SELECT id, substring(name FROM length($1 || '-perf-') + 1)::bigint AS ordinal
			FROM api_keys WHERE name LIKE $1 || '-perf-%'
		)
		INSERT INTO key_ip_audit_ip_state (
			api_key_id, client_ip, first_seen, last_seen, request_count,
			user_agent_count, user_agent, is_baseline
		)
		SELECT id, '203.0.113.150',
		       $2::timestamptz + INTERVAL '1 second',
		       $3::timestamptz - INTERVAL '1 hour' + INTERVAL '1 second',
		       CASE WHEN ordinal % $5 = 0 THEN $6::bigint ELSE $7::bigint END,
		       1, 'perf-agent', TRUE
		FROM perf_keys
		UNION ALL
		SELECT id, '203.0.113.151',
		       $4::timestamptz + INTERVAL '1 second',
		       $3::timestamptz - INTERVAL '1 hour' + INTERVAL '1 second',
		       $6::bigint, 1, 'perf-agent', FALSE
		FROM perf_keys WHERE ordinal % $5 = 0`,
		fixture.prefix, priorFrom, currentTo, currentFrom, keyIPAuditPerfNewIPEvery,
		keyIPAuditPerfHoursPerWindow, 2*keyIPAuditPerfHoursPerWindow)
	require.NoError(t, err)
	ipStateRows, err := ipStateResult.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, keyIPAuditPerfKeyCount+newIPKeyCount, ipStateRows)

	log.Printf("KEY_IP_AUDIT_PERF seed complete: keys=%d facts=%d hour_facts=%d daily_facts=%d hour_key_maxima=%d daily_key_maxima=%d shared_minute_rows=%d rapid_keys=%d new_ip_keys=%d seed_duration=%s",
		keyIPAuditPerfKeyCount, activityRows, hourActivityRollupRows, dailyActivityRollupRows,
		hourKeyRollupRows, dailyKeyRollupRows, sharedMinuteRows,
		rapidKeyCount, newIPKeyCount, time.Since(seedStart))
	for _, table := range []string{
		"api_keys",
		"security_activity_1m",
		"security_activity_rollups",
		"key_ip_audit_key_1m",
		"key_ip_audit_key_rollups",
		"key_ip_audit_ip_1m",
		"key_ip_audit_key_state",
		"key_ip_audit_ip_state",
	} {
		_, err := integrationDB.ExecContext(ctx, "ANALYZE "+table)
		require.NoError(t, err, "analyze %s", table)
	}

	repo := NewKeyIPAuditRepository(integrationDB)
	filter := keyIPAuditFilter(fixture.prefix+"-perf-", currentFrom, currentTo)
	filter.PageSize = 20
	default24hFilter := keyIPAuditFilter(fixture.prefix+"-perf-", currentTo.Add(-24*time.Hour), currentTo)
	default24hFilter.PageSize = filter.PageSize
	var default24h *keyIPAuditKeyListResult
	measureKeyIPAuditPerfRequest(t, ctx, "default 24-hour list (3894-key fixture)", func(callCtx context.Context) error {
		result, listErr := repo.ListKeys(callCtx, default24hFilter)
		if listErr == nil {
			default24h = &keyIPAuditKeyListResult{total: result.Total, items: len(result.Items)}
		}
		return listErr
	})
	require.NotNil(t, default24h)
	require.EqualValues(t, keyIPAuditPerfKeyCount, default24h.total)
	require.Equal(t, default24hFilter.PageSize, default24h.items)
	pauseKeyIPAuditPerfAfterFirstRequest(t)

	var list *keyIPAuditKeyListResult
	measureKeyIPAuditPerfRequest(t, ctx, "30-day list (3894-key fixture)", func(callCtx context.Context) error {
		result, listErr := repo.ListKeys(callCtx, filter)
		if listErr == nil {
			list = &keyIPAuditKeyListResult{total: result.Total, items: len(result.Items)}
		}
		return listErr
	})
	require.NotNil(t, list)
	require.EqualValues(t, keyIPAuditPerfKeyCount, list.total)
	require.Equal(t, filter.PageSize, list.items)

	filteredFilter := filter
	filteredFilter.Signal = "new_ip"
	var filtered *keyIPAuditKeyListResult
	measureKeyIPAuditPerfRequest(t, ctx, "30-day filtered list (signal=new_ip)", func(callCtx context.Context) error {
		result, listErr := repo.ListKeys(callCtx, filteredFilter)
		if listErr == nil {
			filtered = &keyIPAuditKeyListResult{total: result.Total, items: len(result.Items)}
		}
		return listErr
	})
	require.NotNil(t, filtered)
	require.Equal(t, newIPKeyCount, filtered.total)
	require.Equal(t, filter.PageSize, filtered.items)

	var detailKeyID int64
	err = integrationDB.QueryRowContext(ctx,
		`SELECT id FROM api_keys WHERE name = $1 || '-perf-1'`, fixture.prefix).Scan(&detailKeyID)
	require.NoError(t, err)
	detailFilter := filter
	detailFilter.APIKeyID = detailKeyID
	var detailRelatedTotal int64
	measureKeyIPAuditPerfRequest(t, ctx, "30-day key detail with related-IP list", func(callCtx context.Context) error {
		result, detailErr := repo.KeyDetail(callCtx, detailFilter, 1, 20, "203.0.113.150", 1, 20)
		if detailErr == nil {
			detailRelatedTotal = result.RelatedTotal
		}
		return detailErr
	})
	require.EqualValues(t, keyIPAuditPerfKeyCount-newIPKeyCount-1, detailRelatedTotal)

	if os.Getenv("SUB2API_KEY_IP_AUDIT_PERF_EXPLAIN") == "1" {
		explainKeyIPAuditPerfScoreCTE(t, ctx, filter)
	}
}

type keyIPAuditKeyListResult struct {
	total int64
	items int
}

func keyIPAuditPerfUTCDateStart(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}

func pauseKeyIPAuditPerfAfterFirstRequest(t *testing.T) {
	t.Helper()
	if os.Getenv("SUB2API_KEY_IP_AUDIT_PERF_PAUSE_AFTER_FIRST") != "1" {
		return
	}
	fmt.Fprintln(os.Stderr, "KEY_IP_AUDIT_PERF paused after first list; send Enter to continue 30-day list/filter/detail requests")
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err, "wait for perf test continuation")
}

func measureKeyIPAuditPerfRequest(t *testing.T, parent context.Context, label string, call func(context.Context) error) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, keyIPAuditReadTimeout)
	defer cancel()
	start := time.Now()
	err := call(ctx)
	elapsed := time.Since(start)
	log.Printf("KEY_IP_AUDIT_PERF request complete: %s duration=%s deadline=%s err=%v",
		label, elapsed, keyIPAuditReadTimeout, err)
	require.NoError(t, err, "%s must complete before the read deadline", label)
	require.Less(t, elapsed, keyIPAuditReadTimeout, "%s exceeded the repository read deadline", label)
	return elapsed
}

func explainKeyIPAuditPerfScoreCTE(t *testing.T, parent context.Context, filter service.KeyIPAuditFilter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 2*keyIPAuditReadTimeout)
	defer cancel()
	conn, err := integrationDB.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()

	args := keyIPAuditArgs(filter)
	factsSQL := keyIPAuditWindowFacts("$1", "$2", "("+keyIPAuditCandidateKeys+")")
	factPlanRows, err := conn.QueryContext(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) SELECT * FROM ("+factsSQL+") AS facts",
		args...)
	require.NoError(t, err, "explain scored CTE")
	factPlan, err := collectKeyIPAuditPerfPlan(factPlanRows)
	require.NoError(t, err)
	t.Logf("EXPLAIN ANALYZE BUFFERS for current-facts source (excludes temp-table write):\n%s", strings.Join(factPlan, "\n"))

	_, err = conn.ExecContext(ctx, `DROP TABLE IF EXISTS key_ip_audit_current_facts`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `CREATE TEMP TABLE key_ip_audit_current_facts ON COMMIT PRESERVE ROWS AS `+
		factsSQL, args...)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `CREATE INDEX ON key_ip_audit_current_facts (api_key_id, client_ip, bucket_start)`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `ANALYZE key_ip_audit_current_facts`)
	require.NoError(t, err)

	rows, err := conn.QueryContext(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+keyIPAuditMaterializedCTE, args...)
	require.NoError(t, err, "explain scored CTE")
	plan, err := collectKeyIPAuditPerfPlan(rows)
	require.NoError(t, err)
	t.Logf("EXPLAIN ANALYZE BUFFERS for scored CTE (excludes temp-table write and list/summary/coverage/trend queries):\n%s",
		strings.Join(plan, "\n"))
}

func collectKeyIPAuditPerfPlan(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		plan = append(plan, line)
	}
	return plan, rows.Err()
}
