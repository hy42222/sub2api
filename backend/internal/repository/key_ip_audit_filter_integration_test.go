//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKeyIPAuditFilterParityKeyStatus(t *testing.T) {
	tests := []struct {
		name        string
		status      string
		targetState string
		otherState  string
	}{
		{name: "active", status: "active", targetState: "active", otherState: "inactive"},
		{name: "inactive", status: "inactive", targetState: "inactive", otherState: "active"},
		{name: "deleted", status: "deleted", targetState: "deleted", otherState: "active"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newKeyIPAuditFixture(t, "status-target", "status-other")
			from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
			to := from.Add(30 * time.Minute)

			for i, state := range []string{tt.targetState, tt.otherState} {
				rawStatus := state
				deleted := state == "deleted"
				if deleted {
					rawStatus = "active"
				}
				_, err := integrationDB.ExecContext(context.Background(), `
					UPDATE api_keys
					SET status = $2, deleted_at = CASE WHEN $3 THEN NOW() ELSE NULL END
					WHERE id = $1`, fixture.keys[i].ID, rawStatus, deleted)
				require.NoError(t, err)
				insertKeyIPAuditUsageLog(t, fixture.users[i].ID, fixture.keys[i].ID, fixture.account.ID,
					from.Add(time.Minute), []string{"203.0.113.10", "203.0.113.11"}[i])
			}
			projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

			filter := keyIPAuditFilter(fixture.prefix, from, to)
			filter.Status = tt.status
			list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
			require.NoError(t, err)
			require.Equal(t, int64(1), list.Total)
			require.Len(t, list.Items, 1)
			require.Equal(t, fixture.keys[0].ID, list.Items[0].KeyID)
			require.Equal(t, tt.status, list.Items[0].KeyStatus)
			require.Equal(t, int64(1), list.Summary.TotalKeys)
		})
	}
}

func TestKeyIPAuditFilterParityRisk(t *testing.T) {
	tests := []struct {
		name string
		risk string
	}{
		{name: "none", risk: "none"},
		{name: "medium", risk: "medium"},
		{name: "high", risk: "high"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newKeyIPAuditFixture(t, "risk-target", "risk-control")
			from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
			to := from.Add(30 * time.Minute)
			expectedCoverage := int64(1)

			switch tt.risk {
			case "none":
				insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
					from.Add(time.Minute), "203.0.113.20")
				insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID,
					from.Add(-20*time.Minute), "192.0.2.29")
				insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID,
					from.Add(time.Minute), "203.0.113.29")
			case "medium":
				insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
					from.Add(-20*time.Minute), "192.0.2.20")
				insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
					from.Add(time.Minute), "203.0.113.21")
			case "high":
				expectedCoverage = 3
				for i, ip := range []string{"203.0.113.22", "203.0.113.23", "203.0.113.24"} {
					insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
						from.Add(time.Duration(i+1)*time.Minute), ip)
				}
			}
			if tt.risk != "none" {
				insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID,
					from.Add(time.Minute), "203.0.113.29")
			}
			projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

			filter := keyIPAuditFilter(fixture.prefix, from, to)
			filter.Risk = tt.risk
			list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
			require.NoError(t, err)
			require.Equal(t, int64(1), list.Total)
			require.Len(t, list.Items, 1)
			rows := keyIPAuditRowsByID(t, list)
			require.Contains(t, rows, fixture.keys[0].ID)
			require.NotContains(t, rows, fixture.keys[1].ID, "risk filter must exclude the non-matching control key")
			require.Equal(t, tt.risk, rows[fixture.keys[0].ID].RiskLevel)
			require.Equal(t, int64(1), list.Summary.TotalKeys)
			require.Equal(t, expectedCoverage, list.Metadata.Coverage.UsageLogCount)
		})
	}
}

func TestKeyIPAuditFilterParitySignal(t *testing.T) {
	for _, signal := range []string{"new_ip", "multi_ip_burst", "shared_ip_cross_users", "volume_spike"} {
		t.Run(signal, func(t *testing.T) {
			labels := []string{"signal-target", "signal-control"}
			if signal == "shared_ip_cross_users" {
				labels = []string{"shared-first", "shared-second", "nonshared-control"}
			}
			fixture := newKeyIPAuditFixture(t, labels...)
			from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
			to := from.Add(30 * time.Minute)
			expectedCoverage := int64(1)
			targetIDs := []int64{fixture.keys[0].ID}
			controlID := fixture.keys[1].ID
			if signal == "shared_ip_cross_users" {
				targetIDs = []int64{fixture.keys[0].ID, fixture.keys[1].ID}
				controlID = fixture.keys[2].ID
				expectedCoverage = 2
			}

			switch signal {
			case "new_ip":
				insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
					from.Add(-20*time.Minute), "192.0.2.30")
				insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
					from.Add(time.Minute), "203.0.113.30")
			case "multi_ip_burst":
				expectedCoverage = 3
				for i, ip := range []string{"203.0.113.31", "203.0.113.32", "203.0.113.33"} {
					insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
						from.Add(time.Duration(i+1)*time.Minute), ip)
				}
			case "shared_ip_cross_users":
				for i := range targetIDs {
					insertKeyIPAuditUsageLog(t, fixture.users[i].ID, fixture.keys[i].ID, fixture.account.ID,
						from.Add(time.Minute), "203.0.113.34")
				}
				insertKeyIPAuditUsageLog(t, fixture.users[2].ID, fixture.keys[2].ID, fixture.account.ID,
					from.Add(time.Minute), "203.0.113.36")
			case "volume_spike":
				expectedCoverage = 50
				insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
					from.Add(-31*time.Minute), "192.0.2.35")
				for i := 0; i < 50; i++ {
					insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
						from.Add(time.Minute), "203.0.113.35")
				}
			}
			if signal != "shared_ip_cross_users" {
				insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID,
					from.Add(time.Minute), "203.0.113.36")
			}
			projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

			filter := keyIPAuditFilter(fixture.prefix, from, to)
			filter.Signal = signal
			list, err := NewKeyIPAuditRepository(integrationDB).ListKeys(context.Background(), filter)
			require.NoError(t, err)
			require.Equal(t, int64(len(targetIDs)), list.Total)
			require.Len(t, list.Items, len(targetIDs))
			require.Equal(t, int64(len(targetIDs)), list.Summary.TotalKeys)
			require.Equal(t, expectedCoverage, list.Metadata.Coverage.UsageLogCount)
			rows := keyIPAuditRowsByID(t, list)
			for _, targetID := range targetIDs {
				require.Contains(t, rows, targetID)
				require.Contains(t, rows[targetID].RiskReasons, signal)
			}
			require.NotContains(t, rows, controlID, "signal filter must exclude the non-matching control key")
			for _, row := range list.Items {
				require.Contains(t, row.RiskReasons, signal)
			}
			switch signal {
			case "new_ip":
				require.Equal(t, int64(1), list.Summary.NewIPKeys)
			case "multi_ip_burst":
				require.Equal(t, int64(1), list.Summary.MultiIPKeys)
			case "shared_ip_cross_users":
				require.Equal(t, int64(1), list.Summary.SharedIPs)
			case "volume_spike":
				require.Equal(t, int64(1), list.Summary.HighRiskKeys)
			}
		})
	}
}

func TestKeyIPAuditIPFilterKeepsWholeKeyMetricsAndNarrowsCoverageSummary(t *testing.T) {
	fixture := newKeyIPAuditFixture(t, "ip-filter-first", "ip-filter-second")
	from := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	to := from.Add(30 * time.Minute)
	sharedIP := "203.0.113.40"
	filteredIP := "198.51.100.40"

	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
		from.Add(time.Minute), sharedIP)
	insertKeyIPAuditUsageLog(t, fixture.users[1].ID, fixture.keys[1].ID, fixture.account.ID,
		from.Add(time.Minute), sharedIP)
	insertKeyIPAuditUsageLog(t, fixture.users[0].ID, fixture.keys[0].ID, fixture.account.ID,
		from.Add(2*time.Minute), filteredIP)
	projectKeyIPAuditUsageLogs(t, from.Add(-time.Hour))

	repo := NewKeyIPAuditRepository(integrationDB)
	base, err := repo.ListKeys(context.Background(), keyIPAuditFilter(fixture.prefix, from, to))
	require.NoError(t, err)
	require.Equal(t, int64(2), base.Summary.TotalKeys)
	require.Equal(t, int64(1), base.Summary.SharedIPs)
	require.Equal(t, int64(3), base.Metadata.Coverage.UsageLogCount)

	filter := keyIPAuditFilter(fixture.prefix, from, to)
	filter.IP = filteredIP
	filtered, err := repo.ListKeys(context.Background(), filter)
	require.NoError(t, err)
	require.Equal(t, int64(1), filtered.Total)
	require.Equal(t, int64(1), filtered.Summary.TotalKeys)
	require.Zero(t, filtered.Summary.SharedIPs, "summary shared IPs should honor the requested IP")
	require.Equal(t, int64(1), filtered.Metadata.Coverage.UsageLogCount,
		"coverage should count only usage logs matching the requested IP")
	require.Len(t, filtered.Items, 1)
	row := filtered.Items[0]
	require.Equal(t, fixture.keys[0].ID, row.KeyID)
	require.Equal(t, int64(2), row.RequestCount, "IP filtering must retain whole-key request counts")
	require.Equal(t, int64(2), row.IPCount, "IP filtering must retain whole-key IP counts")
	require.Contains(t, row.RiskReasons, "shared_ip_cross_users",
		"the key row should retain whole-key risk evidence outside the requested IP")
}
