//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
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

	list, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Equal(t, int64(1), list.Total)
	require.Equal(t, int64(1), list.Summary.NewIPKeys)
	require.Equal(t, int64(1), list.Summary.PendingKeys)
	require.Equal(t, "open", list.Items[0].Status)
	require.Equal(t, "medium", list.Items[0].RiskLevel)
	require.Equal(t, []string{"new_ip"}, list.Items[0].RiskReasons)
}
