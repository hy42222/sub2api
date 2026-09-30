//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

type keyIPAuditFixture struct {
	prefix  string
	account *service.Account
	users   []*service.User
	keys    []*service.APIKey
}

func newKeyIPAuditFixture(t *testing.T, labels ...string) *keyIPAuditFixture {
	t.Helper()
	client := testEntClient(t)
	prefix := fmt.Sprintf("key-ip-audit-%d", time.Now().UnixNano())
	fixture := &keyIPAuditFixture{prefix: prefix}
	fixture.account = mustCreateAccount(t, client, &service.Account{Name: prefix + "-account"})

	for _, label := range labels {
		user := mustCreateUser(t, client, &service.User{
			Email: prefix + "-" + label + "@example.com",
		})
		key := mustCreateApiKey(t, client, &service.APIKey{
			UserID: user.ID,
			Key:    "sk-" + prefix + "-" + label,
			Name:   prefix + "-" + label,
		})
		fixture.users = append(fixture.users, user)
		fixture.keys = append(fixture.keys, key)
	}

	t.Cleanup(func() {
		ctx := context.Background()
		for _, key := range fixture.keys {
			_, _ = integrationDB.ExecContext(ctx, "DELETE FROM api_keys WHERE id = $1", key.ID)
		}
		if fixture.account != nil {
			_, _ = integrationDB.ExecContext(ctx, "DELETE FROM accounts WHERE id = $1", fixture.account.ID)
		}
		for _, user := range fixture.users {
			_, _ = integrationDB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", user.ID)
		}
	})

	return fixture
}

func insertKeyIPAuditUsageLog(t *testing.T, userID, keyID, accountID int64, createdAt time.Time, ip string) {
	t.Helper()
	_, err := integrationDB.ExecContext(
		context.Background(),
		`INSERT INTO usage_logs
			(user_id, api_key_id, account_id, model, input_tokens, output_tokens, total_cost, actual_cost, user_agent, ip_address, created_at)
		 VALUES ($1, $2, $3, 'key-ip-audit-test', 0, 0, 0, 0, 'key-ip-audit-agent', $4, $5)`,
		userID,
		keyID,
		accountID,
		ip,
		createdAt.UTC(),
	)
	require.NoError(t, err, "insert usage log")
}

func projectKeyIPAuditUsageLogs(t *testing.T, liveSince time.Time) {
	t.Helper()
	_, err := integrationDB.ExecContext(context.Background(), `
		UPDATE key_ip_audit_projection_state
		SET live_since = $1, processed_usage_log_id = 0,
		    processed_created_at = NULL, data_through = NULL,
		    last_successful_at = NULL, updated_at = NOW()
		WHERE id = 1`, liveSince.UTC())
	require.NoError(t, err, "reset key/ip audit projection test boundary")

	repo := NewKeyIPAuditAggregationRepository(integrationDB)
	for i := 0; i < 10; i++ {
		result, processErr := repo.ProcessKeyIPAuditBatch(context.Background(), 1000)
		require.NoError(t, processErr, "project key/ip audit usage logs")
		if result.Processed == 0 {
			return
		}
	}
	t.Fatalf("key/ip audit projection did not drain within test batch limit")
}

func keyIPAuditFilter(prefix string, from, to time.Time) service.KeyIPAuditFilter {
	return service.KeyIPAuditFilter{
		StartTime: from.UTC(),
		EndTime:   to.UTC(),
		KeyQuery:  prefix,
		Page:      1,
		PageSize:  100,
	}
}

func keyIPAuditRowsByID(t *testing.T, list *service.KeyIPAuditKeyList) map[int64]service.KeyIPAuditKeyRow {
	t.Helper()
	rows := make(map[int64]service.KeyIPAuditKeyRow, len(list.Items))
	for _, row := range list.Items {
		rows[row.KeyID] = row
	}
	return rows
}

func TestKeyIPAuditListKeysAggregatesPerKeyAndIPFilter(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "burst", "quiet")
	from := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)

	burstIPs := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"}
	for i, ip := range burstIPs {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(time.Duration(i+1)*time.Minute), ip)
	}
	insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID, from.Add(2*time.Minute), "203.0.113.20")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))
	var projectedRequestCount int64
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT COALESCE(SUM(request_count), 0) FROM security_activity_1m WHERE api_key_id = $1`, fixture.keys[0].ID).Scan(&projectedRequestCount))
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))
	var replayedRequestCount int64
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT COALESCE(SUM(request_count), 0) FROM security_activity_1m WHERE api_key_id = $1`, fixture.keys[0].ID).Scan(&replayedRequestCount))
	require.Equal(t, projectedRequestCount, replayedRequestCount, "replaying projection must not duplicate facts")

	repo := NewKeyIPAuditRepository(integrationDB)
	filter := keyIPAuditFilter(fixture.prefix, from, to)
	list, err := repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Equal(t, int64(2), list.Total)
	require.Len(t, list.Items, 2)
	require.Equal(t, int64(2), list.Summary.TotalKeys)
	require.Equal(t, int64(1), list.Summary.HighRiskKeys)
	require.Equal(t, int64(1), list.Summary.NewIPKeys)
	require.Equal(t, int64(1), list.Summary.MultiIPKeys)
	require.Equal(t, int64(0), list.Summary.SharedIPs)

	rows := keyIPAuditRowsByID(t, list)
	burst := rows[fixture.keys[0].ID]
	require.Equal(t, int64(4), burst.RequestCount)
	require.Equal(t, int64(4), burst.IPCount)
	require.Equal(t, "high", burst.RiskLevel)
	require.Contains(t, burst.RiskReasons, "multi_ip_burst")

	quiet := rows[fixture.keys[1].ID]
	require.Equal(t, int64(1), quiet.RequestCount)
	require.Equal(t, int64(1), quiet.IPCount)
	require.Equal(t, "none", quiet.RiskLevel)

	filter.IP = burstIPs[1]
	filtered, err := repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Equal(t, int64(1), filtered.Total)
	require.Len(t, filtered.Items, 1)
	require.Equal(t, fixture.keys[0].ID, filtered.Items[0].KeyID)
	require.Equal(t, int64(4), filtered.Items[0].RequestCount)
	require.Equal(t, int64(4), filtered.Items[0].IPCount)
	require.Equal(t, "high", filtered.Items[0].RiskLevel)
	require.Equal(t, int64(1), filtered.Summary.HighRiskKeys)
	require.Equal(t, int64(1), filtered.Summary.MultiIPKeys)
}

func TestKeyIPAuditListKeysCarriesBurstAcrossFromAndScopesTrustedCIDR(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "trusted", "other")
	from := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	to := from.Add(40 * time.Minute)

	// Only the first IP is before from, but it remains active in the 10-minute
	// rolling window and is needed to reach the three-IP burst threshold.
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(-5*time.Minute), "192.0.2.10")
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(1*time.Minute), "203.0.113.10")
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(2*time.Minute), "203.0.113.11")

	// Reuse the trusted CIDR on another key outside the first key's rolling
	// window. It must still be a new IP for that key, not trusted globally.
	insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID, from.Add(-20*time.Minute), "198.51.100.20")
	insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID, from.Add(20*time.Minute), "203.0.113.10")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

	repo := NewKeyIPAuditRepository(integrationDB)
	_, err := repo.CreateTrusted(context.Background(), service.KeyIPAuditTrustedInput{
		APIKeyID: fixture.keys[0].ID,
		CIDR:     "203.0.113.0/24",
	})
	require.NoError(t, err)

	list, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Equal(t, int64(2), list.Total)
	require.Equal(t, int64(1), list.Summary.HighRiskKeys)
	require.Equal(t, int64(1), list.Summary.NewIPKeys)
	require.Equal(t, int64(1), list.Summary.MultiIPKeys)
	require.Equal(t, int64(0), list.Summary.SharedIPs)

	rows := keyIPAuditRowsByID(t, list)
	trusted := rows[fixture.keys[0].ID]
	require.Equal(t, int64(2), trusted.IPCount)
	require.Equal(t, int64(0), trusted.NewIPCount)
	require.Equal(t, "high", trusted.RiskLevel)
	require.Equal(t, []string{"multi_ip_burst"}, trusted.RiskReasons)
	multiEvidence, ok := trusted.RiskEvidence["multi_ip_burst"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, int64(3), multiEvidence["distinct_ip_count"])

	other := rows[fixture.keys[1].ID]
	require.Equal(t, int64(1), other.NewIPCount)
	require.Equal(t, "medium", other.RiskLevel)
	require.Equal(t, []string{"new_ip"}, other.RiskReasons)
}

func TestKeyIPAuditDismissalDoesNotSuppressActivityAfterEventEnd(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "dismissed")
	from := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	to := from.Add(20 * time.Minute)
	targetIP := "203.0.113.40"

	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(-20*time.Minute), "192.0.2.40")
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(2*time.Minute), targetIP)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(7*time.Minute), targetIP)

	repo := NewKeyIPAuditRepository(integrationDB)
	_, err := repo.CreateDismissal(context.Background(), service.KeyIPAuditDismissalInput{
		APIKeyID:   fixture.keys[0].ID,
		IP:         targetIP,
		RiskCode:   "new_ip",
		EventStart: from.Add(1 * time.Minute),
		EventEnd:   from.Add(5 * time.Minute),
	})
	require.NoError(t, err)
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

	list, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Equal(t, int64(1), list.Total)
	require.Equal(t, int64(1), list.Summary.NewIPKeys)
	require.Equal(t, int64(1), list.Summary.PendingKeys)
	require.Equal(t, "open", list.Items[0].Status)
	require.Equal(t, "medium", list.Items[0].RiskLevel)
	require.Equal(t, []string{"new_ip"}, list.Items[0].RiskReasons)
}

func TestKeyIPAuditListIncludesKeyWithoutValidIP(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "missing-ip")
	from := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	to := from.Add(20 * time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(time.Minute), "")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Equal(t, int64(1), list.Total)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(1), list.Items[0].RequestCount)
	require.Equal(t, int64(0), list.Items[0].IPCount)
	require.Equal(t, "none", list.Items[0].RiskLevel)
}

func TestKeyIPAuditListIncludesOverlappingMinuteBucket(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "partial-minute")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	from := minute.Add(40 * time.Second)
	to := from.Add(20 * time.Second)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, minute.Add(50*time.Second), "203.0.113.70")
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))

	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Equal(t, int64(1), list.Total)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(1), list.Items[0].RequestCount)
	require.True(t, list.Metadata.Coverage.CoverageComplete, "clipped minute edges have exact event coverage")
}

func TestKeyIPAuditPartialMinutesExcludeEventsOutsideRange(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "exact-edges")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	from, to := minute.Add(40*time.Second), minute.Add(70*time.Second)
	for _, at := range []time.Time{
		minute.Add(5 * time.Second), minute.Add(50 * time.Second),
		minute.Add(65 * time.Second), minute.Add(75 * time.Second),
	} {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, at, "203.0.113.78")
	}
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(2), list.Items[0].RequestCount)
	require.Equal(t, int64(2), list.Metadata.Coverage.UsageLogCount)
	var trendRequestCount int64
	for _, point := range list.Trend {
		trendRequestCount += point.RequestCount
	}
	require.Equal(t, int64(2), trendRequestCount)
}

func TestKeyIPAuditRiskContextCoverageRequiresPriorWindow(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "risk-context")
	from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID,
		fixture.account.ID, from.Add(time.Minute), "203.0.113.79")
	projectKeyIPAuditUsageLogs(t, from.Add(-10*time.Minute))

	repo := NewKeyIPAuditRepository(integrationDB)
	filter := keyIPAuditFilter(fixture.prefix, from, to)
	list, err := repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.True(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "complete", list.Metadata.Coverage.Reason)
	require.False(t, list.Metadata.Coverage.RiskContextComplete)

	projectKeyIPAuditUsageLogs(t, from.Add(-30*time.Minute))
	list, err = repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.True(t, list.Metadata.Coverage.CoverageComplete)
	require.True(t, list.Metadata.Coverage.RiskContextComplete)
	require.Equal(t, int64(1), list.Metadata.Coverage.UsageLogCount)
}

func TestKeyIPAuditMultiresolutionWindowPreservesExactCounts(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "multiresolution")
	day := time.Now().UTC().Truncate(24 * time.Hour).Add(-4 * 24 * time.Hour)
	from := day.Add(9*time.Hour + 17*time.Minute + 40*time.Second)
	to := day.Add(3*24*time.Hour + 11*time.Hour + 31*time.Minute + 20*time.Second)
	priorFrom := from.Add(-to.Sub(from))
	ip := "203.0.113.80"
	for _, at := range []time.Time{
		priorFrom.Add(time.Minute), from.Add(-time.Second),
		from.Add(5 * time.Second), day.Add(10*time.Hour + 10*time.Minute),
		day.Add(24*time.Hour + 12*time.Hour), day.Add(48*time.Hour + 18*time.Hour),
		to.Add(-5 * time.Second), to,
	} {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, at, ip)
	}
	_, err := integrationDB.ExecContext(context.Background(), `INSERT INTO usage_logs
		(user_id, api_key_id, account_id, model, input_tokens, output_tokens, total_cost, actual_cost, user_agent, ip_address, created_at)
		VALUES ($1,$2,$3,'key-ip-audit-test',0,0,0,0,'second-agent',$4,$5)`,
		fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, ip, day.Add(36*time.Hour+time.Minute))
	require.NoError(t, err)
	projectKeyIPAuditUsageLogs(t, priorFrom.Add(-time.Minute))

	repo := NewKeyIPAuditRepository(integrationDB).(*keyIPAuditRepository)
	filter := keyIPAuditFilter(fixture.prefix, from, to)
	list, err := repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(6), list.Items[0].RequestCount)
	require.Equal(t, int64(2), list.Items[0].PriorRequestCount)
	require.Equal(t, int64(6), list.Metadata.Coverage.UsageLogCount)
	var trendTotal int64
	for _, point := range list.Trend {
		trendTotal += point.RequestCount
	}
	require.Equal(t, int64(6), trendTotal)

	filter.APIKeyID = fixture.keys[0].ID
	detail, err := repo.KeyDetail(context.Background(), filter, 1, 20, "", 1, 20)
	require.NoError(t, err)
	require.Len(t, detail.IPs, 1)
	require.Equal(t, int64(2), detail.IPs[0].UserAgentCount)

	ctx, cancel, tx, err := repo.beginKeyIPAuditRead(context.Background())
	require.NoError(t, err)
	defer cancel()
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'America/New_York'`)
	require.NoError(t, err)
	require.NoError(t, createKeyIPAuditScoredTemp(ctx, tx, keyIPAuditArgs(filter)))
	var minuteRows, hourRows, dayRows, count int64
	err = tx.QueryRowContext(ctx, `SELECT
		COUNT(*) FILTER (WHERE bucket_end-bucket_start=INTERVAL '1 minute'),
		COUNT(*) FILTER (WHERE bucket_end-bucket_start=INTERVAL '60 minutes'),
		COUNT(*) FILTER (WHERE bucket_end-bucket_start=INTERVAL '1440 minutes'),
		SUM(request_count) FROM key_ip_audit_current_facts`).Scan(&minuteRows, &hourRows, &dayRows, &count)
	require.NoError(t, err)
	require.Positive(t, minuteRows)
	require.Positive(t, hourRows)
	require.Positive(t, dayRows)
	require.Equal(t, int64(6), count)
	trend, err := queryMaterializedTrend(ctx, tx, append(keyIPAuditArgs(filter), int64(0)), filter)
	require.NoError(t, err)
	var nonUTCTrendRequests int64
	for _, point := range trend {
		require.Equal(t, 0, point.BucketStart.UTC().Hour(), "daily trend buckets must stay UTC-aligned")
		nonUTCTrendRequests += point.RequestCount
	}
	require.Equal(t, int64(6), nonUTCTrendRequests)
}

func TestKeyIPAuditRetentionDoesNotClaimCompleteComparisonHistory(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "retention-coverage")
	from := time.Now().UTC().Truncate(time.Hour).Add(-38 * 24 * time.Hour)
	to := from.Add(30 * 24 * time.Hour)
	priorFrom := from.Add(-30 * 24 * time.Hour)
	for _, at := range []time.Time{priorFrom.Add(time.Minute), from.Add(time.Minute)} {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, at, "203.0.113.81")
	}
	projectKeyIPAuditUsageLogs(t, from.Add(-62*24*time.Hour))
	aggregator := NewKeyIPAuditAggregationRepository(integrationDB)
	require.NoError(t, aggregator.PruneKeyIPAuditProjection(context.Background(), 1000))

	repo := NewKeyIPAuditRepository(integrationDB)
	list, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.True(t, list.Metadata.Coverage.CoverageComplete)
	require.False(t, list.Metadata.Coverage.RiskContextComplete)
	require.Equal(t, int64(1), list.Metadata.Coverage.UsageLogCount)
	require.Zero(t, list.Items[0].PriorRequestCount)

	list, err = repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, priorFrom, priorFrom.Add(24*time.Hour)))
	require.NoError(t, err)
	require.False(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "history_unavailable", list.Metadata.Coverage.Reason)
	require.False(t, list.Metadata.Coverage.RiskContextComplete)
}

func TestKeyIPAuditPruneKeepsMinuteBucketIntersectingRetentionBoundary(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "prune-boundary")
	cutoff := time.Now().UTC().Add(-keyIPAuditProjectionRetention)
	intersecting := cutoff.Add(-30 * time.Second)
	expired := cutoff.Add(-2 * time.Minute)
	_, err := integrationDB.ExecContext(context.Background(), `
		INSERT INTO security_activity_1m (
			bucket_start, api_key_id, user_id, client_ip, user_agent,
			request_count, missing_ip_count, missing_user_agent_count, first_seen, last_seen
		) VALUES
			($1, $3, $4, '203.0.113.90', 'intersecting', 1, 0, 0, $1, $1),
			($2, $3, $4, '203.0.113.91', 'expired', 1, 0, 0, $2, $2)`,
		intersecting, expired, fixture.keys[0].ID, fixture.users[0].ID)
	require.NoError(t, err)

	repo := NewKeyIPAuditAggregationRepository(integrationDB)
	require.NoError(t, repo.PruneKeyIPAuditProjection(context.Background(), 1000))

	var intersectingRows, expiredRows int64
	err = integrationDB.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FILTER (WHERE user_agent='intersecting'),
		       COUNT(*) FILTER (WHERE user_agent='expired')
		FROM security_activity_1m
		WHERE api_key_id=$1 AND user_agent IN ('intersecting','expired')`,
		fixture.keys[0].ID).Scan(&intersectingRows, &expiredRows)
	require.NoError(t, err)
	require.Equal(t, int64(1), intersectingRows)
	require.Zero(t, expiredRows)
}

func TestKeyIPAuditPartialMinuteExcludesEarlierSharedIP(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "shared-edge-first", "shared-edge-second")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	sharedIP := "203.0.113.91"
	for i := range fixture.keys {
		insertKeyIPAuditUsageLog(t, fixture.users[i].ID, fixture.keys[i].ID, fixture.account.ID, minute.Add(5*time.Second), sharedIP)
	}
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, minute.Add(50*time.Second), "203.0.113.92")
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))

	filter := keyIPAuditFilter(fixture.prefix, minute.Add(40*time.Second), minute.Add(time.Minute))
	filter.APIKeyID = fixture.keys[0].ID
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(1), list.Items[0].RequestCount)
	require.NotContains(t, list.Items[0].RiskReasons, "shared_ip_cross_users")
	require.Zero(t, list.Summary.SharedIPs)
}

func TestKeyIPAuditPartialMinuteIncludesBothUsersOfSharedIP(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "shared-order-first", "shared-order-second")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	ip := "203.0.113.93"
	for i, second := range []time.Duration{12, 18} {
		insertKeyIPAuditUsageLog(t, fixture.users[i].ID, fixture.keys[i].ID, fixture.account.ID,
			minute.Add(second*time.Second), ip)
	}
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))
	filter := keyIPAuditFilter(fixture.prefix, minute.Add(10*time.Second), minute.Add(30*time.Second))
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 2)
	for _, row := range list.Items {
		require.Contains(t, row.RiskReasons, "shared_ip_cross_users")
	}
	require.Equal(t, int64(1), list.Summary.SharedIPs)
}

func TestKeyIPAuditPartialMinuteDoesNotUseFutureSharedEvent(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "future-first", "future-second")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	ip := "203.0.113.94"
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, minute.Add(12*time.Second), ip)
	insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID, minute.Add(45*time.Second), ip)
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))
	filter := keyIPAuditFilter(fixture.prefix, minute.Add(10*time.Second), minute.Add(30*time.Second))
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.NotContains(t, list.Items[0].RiskReasons, "shared_ip_cross_users")
	require.Zero(t, list.Summary.SharedIPs)
}

func TestKeyIPAuditPartialMinuteExcludesEarlierBurst(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "burst-edge")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	for i, second := range []time.Duration{30, 35} {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
			minute.Add(-10*time.Minute+second*time.Second), fmt.Sprintf("203.0.113.%d", 101+i))
	}
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
		minute.Add(20*time.Second), "203.0.113.103")
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
		minute.Add(50*time.Second), "203.0.113.104")
	projectKeyIPAuditUsageLogs(t, minute.Add(-11*time.Minute))

	filter := keyIPAuditFilter(fixture.prefix, minute.Add(40*time.Second), minute.Add(time.Minute))
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(1), list.Items[0].RequestCount)
	require.NotContains(t, list.Items[0].RiskReasons, "multi_ip_burst")
}

func TestKeyIPAuditDismissalDoesNotUseOutOfRangeBurstAnchor(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "dismiss-edge-anchor")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	for i, second := range []time.Duration{30, 35} {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
			minute.Add(-10*time.Minute+second*time.Second), fmt.Sprintf("203.0.113.%d", 131+i))
	}
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
		minute.Add(10*time.Second), "203.0.113.133")
	at := minute.Add(50 * time.Second)
	ip := "203.0.113.134"
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, at, ip)
	projectKeyIPAuditUsageLogs(t, minute.Add(-11*time.Minute))
	repo := NewKeyIPAuditRepository(integrationDB)
	_, err := repo.CreateDismissal(context.Background(), service.KeyIPAuditDismissalInput{
		APIKeyID: fixture.keys[0].ID, IP: ip, RiskCode: "multi_ip_burst",
		EventStart: at.Add(-time.Second), EventEnd: at.Add(time.Second),
	})
	require.NoError(t, err)
	filter := keyIPAuditFilter(fixture.prefix, minute.Add(40*time.Second), minute.Add(time.Minute))
	list, err := repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.NotContains(t, list.Items[0].RiskReasons, "multi_ip_burst")
	require.Zero(t, list.Summary.MultiIPKeys)
}

func TestKeyIPAuditTenMinuteLookbackIncludesPreviousTenthBucket(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "ten-minute-boundary")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	first := minute.Add(59 * time.Second)
	for i, at := range []time.Time{first, minute.Add(10 * time.Minute), minute.Add(10*time.Minute + time.Second)} {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
			at, fmt.Sprintf("203.0.113.%d", 141+i))
	}
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))
	filter := keyIPAuditFilter(fixture.prefix, minute.Add(10*time.Minute), minute.Add(11*time.Minute))
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Contains(t, list.Items[0].RiskReasons, "multi_ip_burst")
}

func TestKeyIPAuditDismissAllBurstIPsRemovesBurstRisk(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "burst-dismiss-all")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	repo := NewKeyIPAuditRepository(integrationDB)
	for i := range 3 {
		at := minute.Add(time.Duration(i+1) * time.Second)
		ip := fmt.Sprintf("203.0.113.%d", 111+i)
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, at, ip)
		_, err := repo.CreateDismissal(context.Background(), service.KeyIPAuditDismissalInput{
			APIKeyID: fixture.keys[0].ID, IP: ip, RiskCode: "multi_ip_burst",
			EventStart: at.Add(-time.Second), EventEnd: at.Add(time.Second),
		})
		require.NoError(t, err)
	}
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))
	_, err := repo.CreateTrusted(context.Background(), service.KeyIPAuditTrustedInput{
		APIKeyID: fixture.keys[0].ID, CIDR: "203.0.113.0/24",
	})
	require.NoError(t, err)

	list, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, minute, minute.Add(time.Minute)))
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, "none", list.Items[0].RiskLevel)
	require.NotContains(t, list.Items[0].RiskReasons, "multi_ip_burst")
	require.Equal(t, int64(0), list.Summary.MultiIPKeys)
}

func TestKeyIPAuditProjectionDistinguishesRepeatedSourceIDs(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "partition-identity")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, minute.Add(time.Minute), "203.0.113.121")
	var id int64
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT id FROM usage_logs WHERE api_key_id=$1 ORDER BY id DESC LIMIT 1`, fixture.keys[0].ID).Scan(&id))
	_, err := integrationDB.ExecContext(context.Background(), `
		INSERT INTO security_activity_projection_queue
			(source_relation, usage_log_id, api_key_id, user_id, ip_address, user_agent, created_at)
		VALUES ('public.usage_logs_other_partition', $1, $2, $3, '203.0.113.122', 'key-ip-audit-agent', $4),
		       ('public.usage_logs', $1, $2, $3, '203.0.113.123', 'key-ip-audit-agent', $4 + INTERVAL '1 minute')`,
		id, fixture.keys[0].ID, fixture.users[0].ID, minute.Add(2*time.Minute))
	require.NoError(t, err)
	projectKeyIPAuditUsageLogs(t, minute.Add(-time.Minute))

	var eventCount int64
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM security_activity_events WHERE usage_log_id=$1`, id).Scan(&eventCount))
	require.Equal(t, int64(3), eventCount)
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(),
		keyIPAuditFilter(fixture.prefix, minute, minute.Add(5*time.Minute)))
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(3), list.Items[0].RequestCount)
}

func TestKeyIPAuditProjectionKeepsQueuedEventWithEarlierTransactionTimestamp(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "earlier-transaction")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
		minute.Add(time.Minute), "203.0.113.123")
	// A transaction opened before the migration can insert after its trigger is
	// installed while created_at still reflects the earlier transaction start.
	projectKeyIPAuditUsageLogs(t, minute.Add(2*time.Minute))
	var eventCount int64
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM security_activity_events WHERE api_key_id=$1`, fixture.keys[0].ID).Scan(&eventCount))
	require.Equal(t, int64(1), eventCount)
}

func TestKeyIPAuditMigrationEnqueuesDuplicateIDsFromDistinctPartitions(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "partitioned-parent")
	ctx := context.Background()
	tx, err := integrationDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })

	schema := fmt.Sprintf("key_ip_audit_partition_%d", fixture.keys[0].ID)
	_, err = tx.ExecContext(ctx, "CREATE SCHEMA "+pq.QuoteIdentifier(schema))
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "SET LOCAL search_path TO "+pq.QuoteIdentifier(schema)+", public")
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `
		CREATE TABLE usage_logs (
			id BIGINT NOT NULL, api_key_id BIGINT, user_id BIGINT,
			ip_address TEXT, user_agent TEXT, created_at TIMESTAMPTZ NOT NULL
		) PARTITION BY RANGE (created_at);
		CREATE TABLE usage_logs_day_one PARTITION OF usage_logs
			FOR VALUES FROM ('2026-09-20') TO ('2026-09-21');
		CREATE TABLE usage_logs_day_two PARTITION OF usage_logs
			FOR VALUES FROM ('2026-09-21') TO ('2026-09-22');`)
	require.NoError(t, err)
	content, err := migrations.FS.ReadFile("240_security_activity_key_ip_audit_projection.sql")
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, string(content))
	require.NoError(t, err, "projection migration must work with a partitioned usage_logs parent")
	_, err = tx.ExecContext(ctx, `
		INSERT INTO usage_logs (id, api_key_id, user_id, ip_address, created_at)
		VALUES (42, $1, $2, '203.0.113.124', '2026-09-20T12:00:00Z'),
		       (42, $1, $2, '203.0.113.125', '2026-09-20T13:00:00Z'),
		       (42, $1, $2, '203.0.113.126', '2026-09-21T12:00:00Z')`,
		fixture.keys[0].ID, fixture.users[0].ID)
	require.NoError(t, err)
	var queued int64
	require.NoError(t, tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM security_activity_projection_queue WHERE usage_log_id=42`).Scan(&queued))
	require.Equal(t, int64(3), queued)
}

func TestKeyIPAuditPartialMinuteDismissalDoesNotHideUndismissedRequests(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "partial-dismissal")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	from, to := minute, minute.Add(time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, minute.Add(-time.Minute), "203.0.113.77")
	for _, second := range []time.Duration{5, 55} {
		insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, minute.Add(second*time.Second), "203.0.113.79")
	}
	repo := NewKeyIPAuditRepository(integrationDB)
	_, err := repo.CreateDismissal(context.Background(), service.KeyIPAuditDismissalInput{
		APIKeyID: fixture.keys[0].ID, IP: "203.0.113.79", RiskCode: "new_ip",
		EventStart: minute.Add(25 * time.Second), EventEnd: minute.Add(26 * time.Second),
	})
	require.NoError(t, err)
	projectKeyIPAuditUsageLogs(t, minute.Add(-2*time.Minute))
	list, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(2), list.Items[0].RequestCount)
	require.Equal(t, int64(1), list.Items[0].NewIPCount)
	require.Equal(t, "medium", list.Items[0].RiskLevel)
}

func TestKeyIPAuditPendingLateEventKeepsCoverageIncomplete(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "pending-late")
	from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(2*time.Minute), "203.0.113.80")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))
	// This insert commits after the last projection scan but has an older event time.
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(time.Minute), "203.0.113.81")
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.False(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "projection_pending", list.Metadata.Coverage.Reason)
	require.False(t, list.Metadata.Coverage.DataThrough.After(from.Add(time.Minute)))
}

func TestKeyIPAuditPendingPreBoundaryEventKeepsCoverageIncomplete(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "pending-pre-boundary")
	from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(time.Minute), "203.0.113.83")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))
	// A transaction that started before the projection migration can enqueue a
	// new event with a timestamp older than its live boundary.
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(-2*time.Minute), "203.0.113.84")
	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.False(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "projection_pending", list.Metadata.Coverage.Reason)
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))
	list, err = NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.True(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "complete", list.Metadata.Coverage.Reason)
}

func TestKeyIPAuditCoverageIgnoresPendingEventsOutsideSelectedKeysAndWindow(t *testing.T) {
	selected := newKeyIPAuditFixture(t, "selected")
	unrelated := newKeyIPAuditFixture(t, "unrelated")
	from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)
	insertKeyIPAuditUsageLog(t, selected.users[0].ID, selected.keys[0].ID, selected.account.ID, from.Add(time.Minute), "203.0.113.85")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))

	// Neither an event for another key inside the range nor an event for the
	// selected key after the range can change this query's projection.
	insertKeyIPAuditUsageLog(t, unrelated.users[0].ID, unrelated.keys[0].ID, unrelated.account.ID, from.Add(2*time.Minute), "203.0.113.86")
	insertKeyIPAuditUsageLog(t, selected.users[0].ID, selected.keys[0].ID, selected.account.ID, to.Add(time.Minute), "203.0.113.87")

	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(selected.prefix, from, to))
	require.NoError(t, err)
	require.True(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "complete", list.Metadata.Coverage.Reason)
}

func TestKeyIPAuditCoverageIncludesPendingSharedIPPeer(t *testing.T) {
	selected := newKeyIPAuditFixture(t, "selected-shared")
	peer := newKeyIPAuditFixture(t, "peer-shared")
	from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)
	sharedIP := "2001:db8::88"
	insertKeyIPAuditUsageLog(t, selected.users[0].ID, selected.keys[0].ID, selected.account.ID, from.Add(2*time.Minute), sharedIP)
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))

	// A pending peer event can turn the selected key's activity into a shared-IP
	// signal even though the peer key itself is outside the key filter.
	insertKeyIPAuditUsageLog(t, peer.users[0].ID, peer.keys[0].ID, peer.account.ID, from.Add(time.Minute), "2001:0db8:0000:0000:0000:0000:0000:0088")

	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(selected.prefix, from, to))
	require.NoError(t, err)
	require.False(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "projection_pending", list.Metadata.Coverage.Reason)
}

func TestKeyIPAuditDismissedSharedMinuteIsNotRevivedByLaterActivity(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "shared-first", "shared-second")
	from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)
	ip := "203.0.113.82"
	sharedAt := from.Add(2 * time.Minute)
	for i := range fixture.keys {
		insertKeyIPAuditUsageLog(t, fixture.users[i].ID, fixture.keys[i].ID, fixture.account.ID, sharedAt, ip)
	}
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(25*time.Minute), ip)
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))

	repo := NewKeyIPAuditRepository(integrationDB)
	_, err := repo.CreateDismissal(context.Background(), service.KeyIPAuditDismissalInput{
		APIKeyID: fixture.keys[0].ID, IP: ip, RiskCode: "shared_ip_cross_users",
		EventStart: sharedAt.Add(-time.Second), EventEnd: sharedAt.Add(time.Second),
	})
	require.NoError(t, err)
	filter := keyIPAuditFilter(fixture.prefix, from, to)
	filter.APIKeyID = fixture.keys[0].ID
	list, err := repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.NotContains(t, list.Items[0].RiskReasons, "shared_ip_cross_users")
	require.Equal(t, int64(0), list.Summary.SharedIPs)
}

func TestKeyIPAuditProjectionProcessesLateEventAndPromotesBaseline(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "late-event")
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	from := minute
	to := from.Add(10 * time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(2*time.Minute), "203.0.113.72")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))

	// This event has an older event time but is inserted after the projection
	// already advanced. The queue must still deliver it.
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(time.Minute), "203.0.113.71")
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Minute))

	var baselineIP string
	var firstIPBaseline, secondIPBaseline bool
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT client_ip, is_baseline
		FROM key_ip_audit_ip_state
		WHERE api_key_id = $1 AND client_ip = '203.0.113.71'`, fixture.keys[0].ID).Scan(&baselineIP, &firstIPBaseline))
	require.NoError(t, integrationDB.QueryRowContext(context.Background(), `
		SELECT is_baseline
		FROM key_ip_audit_ip_state
		WHERE api_key_id = $1 AND client_ip = '203.0.113.72'`, fixture.keys[0].ID).Scan(&secondIPBaseline))
	require.Equal(t, "203.0.113.71", baselineIP)
	require.True(t, firstIPBaseline)
	require.False(t, secondIPBaseline)

	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(2), list.Items[0].RequestCount)
	require.Equal(t, int64(1), list.Items[0].NewIPCount)
}

func TestKeyIPAuditTrustedIPIsNotReportedAsDismissed(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "trusted-only")
	from := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	to := from.Add(20 * time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(-5*time.Minute), "192.0.2.50")
	targetIP := "203.0.113.50"
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(time.Minute), targetIP)
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

	repo := NewKeyIPAuditRepository(integrationDB)
	_, err := repo.CreateTrusted(context.Background(), service.KeyIPAuditTrustedInput{
		APIKeyID: fixture.keys[0].ID,
		CIDR:     "203.0.113.0/24",
	})
	require.NoError(t, err)

	list, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, int64(0), list.Items[0].NewIPCount)
	require.Equal(t, "none", list.Items[0].RiskLevel)
	require.Equal(t, "normal", list.Items[0].Status)
}

func TestKeyIPAuditHistoryBeforeProjectionBoundaryIsMarkedUncovered(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "historical")
	from := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	to := from.Add(20 * time.Minute)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID, from.Add(time.Minute), "203.0.113.60")

	// Model an event enqueued before the feature's live boundary. Only new
	// enqueues are projected, even when old events are still in the source.
	_, err := integrationDB.ExecContext(context.Background(), `
		UPDATE security_activity_projection_queue SET enqueued_at=$1 WHERE api_key_id=$2`,
		from.Add(time.Minute), fixture.keys[0].ID)
	require.NoError(t, err)
	projectKeyIPAuditUsageLogs(t, from.Add(time.Hour))

	list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Empty(t, list.Items)
	require.Equal(t, int64(0), list.Total)
	require.False(t, list.Metadata.Coverage.CoverageComplete)
	require.Equal(t, "history_unavailable", list.Metadata.Coverage.Reason)
	require.Equal(t, "security_activity_projection", list.Metadata.Coverage.Source)
}
