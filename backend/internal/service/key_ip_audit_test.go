package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKeyIPAuditNormalizeFilter(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("test", 8*60*60))

	filter := &KeyIPAuditFilter{
		EndTime:   now,
		KeyQuery:  "  example-key  ",
		UserQuery: "  owner@example.com  ",
		IP:        " ::ffff:192.0.2.10 ",
		Risk:      " HIGH ",
		Status:    " ALL ",
		Signal:    " ALL ",
	}
	require.NoError(t, NormalizeKeyIPAuditFilter(filter, now))
	require.Equal(t, now.UTC(), filter.EndTime)
	require.Equal(t, now.UTC().Add(-KeyIPAuditDefaultRange), filter.StartTime)
	require.Equal(t, "example-key", filter.KeyQuery)
	require.Equal(t, "owner@example.com", filter.UserQuery)
	require.Equal(t, "192.0.2.10", filter.IP)
	require.Equal(t, "high", filter.Risk)
	require.Empty(t, filter.Status)
	require.Empty(t, filter.Signal)
	require.Equal(t, KeyIPAuditDefaultPage, filter.Page)
	require.Equal(t, KeyIPAuditDefaultSize, filter.PageSize)

	invalid := []struct {
		name   string
		filter *KeyIPAuditFilter
	}{
		{name: "nil", filter: nil},
		{name: "empty range", filter: &KeyIPAuditFilter{StartTime: now, EndTime: now}},
		{name: "future", filter: &KeyIPAuditFilter{EndTime: now.Add(3 * time.Minute)}},
		{name: "negative id", filter: &KeyIPAuditFilter{APIKeyID: -1}},
		{name: "invalid ip", filter: &KeyIPAuditFilter{IP: "not-an-ip"}},
		{name: "invalid risk", filter: &KeyIPAuditFilter{Risk: "critical"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			err := NormalizeKeyIPAuditFilter(tc.filter, now)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrKeyIPAuditInvalidFilter)
		})
	}
}

func TestKeyIPAuditNormalizeTrustedCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "ipv4 address", input: " 192.0.2.7 ", want: "192.0.2.7/32"},
		{name: "ipv4 network", input: "192.0.2.7/24", want: "192.0.2.0/24"},
		{name: "mapped ipv6 network", input: "::ffff:192.0.2.7/120", want: "192.0.2.0/24"},
		{name: "ipv6 address", input: "2001:db8::7", want: "2001:db8::7/128"},
		{name: "ipv6 network", input: "2001:db8::7/64", want: "2001:db8::/64"},
		{name: "invalid", input: "192.0.2.7/33", wantErr: true},
		{name: "missing", input: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeTrustedCIDR(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrKeyIPAuditInvalidFilter)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestKeyIPAuditKeyRowFromAggregateRisk(t *testing.T) {
	tests := []struct {
		name          string
		aggregate     KeyIPAuditKeyAggregate
		wantLevel     string
		wantReasons   []string
		wantStatus    string
		wantChangePct float64
		wantPct       bool
	}{
		{
			name:        "new ip is medium and open",
			aggregate:   KeyIPAuditKeyAggregate{NewIPCount: 1},
			wantLevel:   "medium",
			wantReasons: []string{"new_ip"},
			wantStatus:  "open",
		},
		{
			name:        "burst takes high precedence",
			aggregate:   KeyIPAuditKeyAggregate{RapidIPCount: KeyIPAuditBurstIPCount},
			wantLevel:   "high",
			wantReasons: []string{"multi_ip_burst"},
			wantStatus:  "open",
		},
		{
			name:        "new ip and volume are high",
			aggregate:   KeyIPAuditKeyAggregate{NewIPCount: 1, VolumeSpike: true},
			wantLevel:   "high",
			wantReasons: []string{"new_ip", "volume_spike"},
			wantStatus:  "open",
		},
		{
			name: "dismissed raw risk",
			aggregate: KeyIPAuditKeyAggregate{
				RawNewIPCount: 1,
				DismissedAny:  true,
			},
			wantLevel:  "none",
			wantStatus: "dismissed",
		},
		{
			name: "normal key keeps volume change evidence separate from risk",
			aggregate: KeyIPAuditKeyAggregate{
				RequestCount:             30,
				PriorRequestCount:        10,
				CurrentRequestCount:      30,
				PriorRequestCountForRisk: 10,
			},
			wantLevel:     "none",
			wantStatus:    "normal",
			wantChangePct: 200,
			wantPct:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := KeyIPAuditKeyRowFromAggregate(tc.aggregate)
			require.Equal(t, tc.wantLevel, row.RiskLevel)
			if len(tc.wantReasons) == 0 {
				require.Empty(t, row.RiskReasons)
			} else {
				require.Equal(t, tc.wantReasons, row.RiskReasons)
			}
			require.Equal(t, tc.wantStatus, row.Status)
			if tc.wantPct {
				require.NotNil(t, row.RequestCountChangePct)
				require.InDelta(t, tc.wantChangePct, *row.RequestCountChangePct, 0.001)
			} else {
				require.Nil(t, row.RequestCountChangePct)
			}
		})
	}
}
