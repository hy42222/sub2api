package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	KeyIPAuditDefaultRange  = 24 * time.Hour
	KeyIPAuditMaxRange      = 30 * 24 * time.Hour
	KeyIPAuditRollingWindow = 10 * time.Minute
	KeyIPAuditDefaultPage   = 1
	KeyIPAuditDefaultSize   = 20
	KeyIPAuditMaxPageSize   = 100
	KeyIPAuditBurstIPCount  = 3
)

var (
	ErrKeyIPAuditInvalidFilter     = errors.New("invalid key/ip audit filter")
	ErrKeyIPAuditTrustedNotFound   = errors.New("trusted ip rule not found")
	ErrKeyIPAuditDismissalNotFound = errors.New("key/ip audit dismissal not found")
)

// KeyIPAuditFilter contains the dimensions accepted by both key endpoints.
// Zero IDs and empty strings mean that the dimension is not constrained.
type KeyIPAuditFilter struct {
	StartTime time.Time
	EndTime   time.Time
	APIKeyID  int64
	UserID    int64
	KeyQuery  string
	UserQuery string
	IP        string
	Risk      string
	Status    string
	Signal    string
	Page      int
	PageSize  int
}

type KeyIPAuditCoverage struct {
	Source                string  `json:"source"`
	UsageLogCount         int64   `json:"usage_log_count"`
	MissingIPCount        int64   `json:"missing_ip_count"`
	MissingUserAgentCount int64   `json:"missing_user_agent_count"`
	IPCoveragePercent     float64 `json:"ip_coverage_percent"`
}

type KeyIPAuditMetadata struct {
	From     time.Time          `json:"from"`
	To       time.Time          `json:"to"`
	Coverage KeyIPAuditCoverage `json:"coverage"`
}

type KeyIPAuditKeySummary struct {
	TotalKeys    int64 `json:"total_keys"`
	HighRiskKeys int64 `json:"high_risk_keys"`
	NewIPKeys    int64 `json:"new_ip_keys"`
	MultiIPKeys  int64 `json:"multi_ip_keys"`
	SharedIPs    int64 `json:"shared_ips"`
	PendingKeys  int64 `json:"pending_keys"`
}

type KeyIPAuditTrendPoint struct {
	BucketStart  time.Time `json:"bucket_start"`
	RequestCount int64     `json:"request_count"`
	RiskyKeys    int64     `json:"risky_keys"`
}

type KeyIPAuditKeyRow struct {
	KeyID                 int64          `json:"key_id"`
	KeyName               string         `json:"key_name"`
	KeyPrefix             string         `json:"key_prefix"`
	KeyStatus             string         `json:"key_status"`
	UserID                int64          `json:"user_id"`
	UserEmail             string         `json:"user_email"`
	LatestIP              *string        `json:"latest_ip"`
	IPCount               int64          `json:"ip_count"`
	NewIPCount            int64          `json:"new_ip_count"`
	FirstSeen             time.Time      `json:"first_seen"`
	LastSeen              time.Time      `json:"last_seen"`
	RequestCount          int64          `json:"request_count"`
	PriorRequestCount     int64          `json:"prior_request_count"`
	RequestCountChangePct *float64       `json:"request_count_change_pct"`
	RiskLevel             string         `json:"risk_level"`
	RiskReasons           []string       `json:"risk_reasons"`
	RiskEvidence          map[string]any `json:"risk_evidence"`
	Status                string         `json:"status"`
}

type KeyIPAuditKeyList struct {
	Items    []KeyIPAuditKeyRow     `json:"items"`
	Total    int64                  `json:"total"`
	Page     int                    `json:"page"`
	PageSize int                    `json:"page_size"`
	Summary  KeyIPAuditKeySummary   `json:"summary"`
	Trend    []KeyIPAuditTrendPoint `json:"trend"`
	Metadata KeyIPAuditMetadata     `json:"metadata"`
}

type KeyIPAuditIPRow struct {
	IP             string    `json:"ip"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	RequestCount   int64     `json:"request_count"`
	UserAgent      string    `json:"user_agent"`
	UserAgentCount int64     `json:"user_agent_count"`
	NewIP          bool      `json:"new_ip"`
	Trusted        bool      `json:"trusted"`
	Geo            *string   `json:"geo"`
	ASN            *string   `json:"asn"`
}

type KeyIPAuditKeyDetail struct {
	Key             KeyIPAuditKeyRow        `json:"key"`
	IPs             []KeyIPAuditIPRow       `json:"ips"`
	IPsTotal        int64                   `json:"ips_total"`
	IPsPage         int                     `json:"ips_page"`
	IPsPageSize     int                     `json:"ips_page_size"`
	RelatedKeys     []KeyIPAuditKeyRow      `json:"related_keys"`
	RelatedTotal    int64                   `json:"related_total"`
	RelatedPage     int                     `json:"related_page"`
	RelatedPageSize int                     `json:"related_page_size"`
	RelatedIP       string                  `json:"related_ip"`
	TrustedRules    []KeyIPAuditTrustedRule `json:"trusted_rules"`
	TrustedTotal    int64                   `json:"trusted_total"`
	Trend           []KeyIPAuditTrendPoint  `json:"trend"`
	Metadata        KeyIPAuditMetadata      `json:"metadata"`
}

type KeyIPAuditTrustedRule struct {
	ID        int64      `json:"id"`
	APIKeyID  int64      `json:"key_id"`
	CIDR      string     `json:"cidr"`
	Note      string     `json:"note"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedBy *int64     `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type KeyIPAuditTrustedInput struct {
	APIKeyID  int64
	CIDR      string
	Note      string
	ExpiresAt *time.Time
	CreatedBy *int64
}

type KeyIPAuditDismissal struct {
	ID         int64     `json:"id"`
	APIKeyID   int64     `json:"key_id"`
	IP         string    `json:"ip"`
	RiskCode   string    `json:"risk_code"`
	EventStart time.Time `json:"event_start"`
	EventEnd   time.Time `json:"event_end"`
	Note       string    `json:"note"`
	CreatedBy  *int64    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type KeyIPAuditDismissalInput struct {
	APIKeyID   int64
	IP         string
	RiskCode   string
	EventStart time.Time
	EventEnd   time.Time
	Note       string
	CreatedBy  *int64
}

// KeyIPAuditKeyAggregate is the database-facing, key-level evidence model.
// It contains no credential and is converted to the response row in one place.
type KeyIPAuditKeyAggregate struct {
	KeyID                    int64
	KeyName                  string
	KeyPrefix                string
	KeyStatus                string
	UserID                   int64
	UserEmail                string
	LatestIP                 *string
	IPCount                  int64
	NewIPCount               int64
	FirstSeen                time.Time
	LastSeen                 time.Time
	RequestCount             int64
	PriorRequestCount        int64
	RawNewIPCount            int64
	RawRapidIPCount          int64
	RawSharedIPCount         int64
	RawVolumeSpike           bool
	RapidIPCount             int64
	SharedIPCount            int64
	VolumeSpike              bool
	CurrentRequestCount      int64
	PriorRequestCountForRisk int64
	DismissedAny             bool
}

type KeyIPAuditIPAggregate struct {
	IP             string
	FirstSeen      time.Time
	LastSeen       time.Time
	RequestCount   int64
	UserAgent      string
	UserAgentCount int64
	NewIP          bool
	Trusted        bool
}

// KeyIPAuditRiskLevel is the canonical precedence used by both service
// conversion and repository SQL. A trusted IP only suppresses its new_ip
// contribution; it never removes a burst or another IP's signal.
func KeyIPAuditRiskLevel(newIP, multiIP, sharedIP, volumeSpike bool) string {
	if multiIP || (newIP && volumeSpike) {
		return "high"
	}
	if newIP || sharedIP || volumeSpike {
		return "medium"
	}
	return "none"
}

func KeyIPAuditRiskReasons(newIP, multiIP, sharedIP, volumeSpike bool) []string {
	reasons := make([]string, 0, 4)
	if newIP {
		reasons = append(reasons, "new_ip")
	}
	if multiIP {
		reasons = append(reasons, "multi_ip_burst")
	}
	if sharedIP {
		reasons = append(reasons, "shared_ip_cross_users")
	}
	if volumeSpike {
		reasons = append(reasons, "volume_spike")
	}
	return reasons
}

func KeyIPAuditKeyRowFromAggregate(a KeyIPAuditKeyAggregate) KeyIPAuditKeyRow {
	newIP := a.NewIPCount > 0
	multiIP := a.RapidIPCount >= KeyIPAuditBurstIPCount
	sharedIP := a.SharedIPCount > 0
	reasons := KeyIPAuditRiskReasons(newIP, multiIP, sharedIP, a.VolumeSpike)
	rawReasons := KeyIPAuditRiskReasons(
		a.RawNewIPCount > 0,
		a.RawRapidIPCount >= KeyIPAuditBurstIPCount,
		a.RawSharedIPCount > 0,
		a.RawVolumeSpike,
	)
	row := KeyIPAuditKeyRow{
		KeyID:             a.KeyID,
		KeyName:           a.KeyName,
		KeyPrefix:         a.KeyPrefix,
		KeyStatus:         a.KeyStatus,
		UserID:            a.UserID,
		UserEmail:         a.UserEmail,
		LatestIP:          a.LatestIP,
		IPCount:           a.IPCount,
		NewIPCount:        a.NewIPCount,
		FirstSeen:         a.FirstSeen,
		LastSeen:          a.LastSeen,
		RequestCount:      a.RequestCount,
		PriorRequestCount: a.PriorRequestCount,
		RiskLevel:         KeyIPAuditRiskLevel(newIP, multiIP, sharedIP, a.VolumeSpike),
		RiskReasons:       reasons,
		RiskEvidence:      make(map[string]any),
		Status:            "normal",
	}
	if a.PriorRequestCount > 0 {
		pct := float64(a.RequestCount-a.PriorRequestCount) * 100 / float64(a.PriorRequestCount)
		row.RequestCountChangePct = &pct
	}
	if newIP {
		row.RiskEvidence["new_ip"] = map[string]any{"new_ip_count": a.NewIPCount}
	}
	if multiIP {
		row.RiskEvidence["multi_ip_burst"] = map[string]any{
			"window":            KeyIPAuditRollingWindow.String(),
			"distinct_ip_count": a.RapidIPCount,
			"threshold":         KeyIPAuditBurstIPCount,
		}
	}
	if sharedIP {
		row.RiskEvidence["shared_ip_cross_users"] = map[string]any{
			"shared_ip_count": a.SharedIPCount,
			"window":          KeyIPAuditRollingWindow.String(),
			"nat_possible":    true,
			"leakage_proven":  false,
		}
	}
	if a.VolumeSpike {
		row.RiskEvidence["volume_spike"] = map[string]any{
			"current_request_count":  a.CurrentRequestCount,
			"previous_request_count": a.PriorRequestCountForRisk,
		}
	}
	if len(reasons) == 0 && len(rawReasons) > 0 && a.DismissedAny {
		row.Status = "dismissed"
	} else if len(reasons) > 0 {
		row.Status = "open"
	}
	return row
}

// KeyIPAuditRepository owns aggregate SQL and disposition persistence.
type KeyIPAuditRepository interface {
	ListKeys(ctx context.Context, filter KeyIPAuditFilter) (*KeyIPAuditKeyList, error)
	KeyDetail(ctx context.Context, filter KeyIPAuditFilter, ipPage, ipPageSize int, relatedIP string, relatedPage, relatedPageSize int) (*KeyIPAuditKeyDetail, error)
	ListTrusted(ctx context.Context, apiKeyID int64, page, pageSize int) ([]KeyIPAuditTrustedRule, int64, error)
	CreateTrusted(ctx context.Context, input KeyIPAuditTrustedInput) (*KeyIPAuditTrustedRule, error)
	DeleteTrusted(ctx context.Context, id int64) error
	CreateDismissal(ctx context.Context, input KeyIPAuditDismissalInput) (*KeyIPAuditDismissal, error)
	DeleteDismissal(ctx context.Context, id int64) error
}

type KeyIPAuditService struct {
	repo          KeyIPAuditRepository
	apiKeyService *APIKeyService
}

func NewKeyIPAuditService(repo KeyIPAuditRepository, apiKeyService *APIKeyService) *KeyIPAuditService {
	return &KeyIPAuditService{repo: repo, apiKeyService: apiKeyService}
}

func (s *KeyIPAuditService) ListKeys(ctx context.Context, filter KeyIPAuditFilter) (*KeyIPAuditKeyList, error) {
	if err := NormalizeKeyIPAuditFilter(&filter, time.Now().UTC()); err != nil {
		return nil, err
	}
	return s.repo.ListKeys(ctx, filter)
}

func (s *KeyIPAuditService) KeyDetail(ctx context.Context, filter KeyIPAuditFilter, ipPage, ipPageSize int, relatedIP string, relatedPage, relatedPageSize int) (*KeyIPAuditKeyDetail, error) {
	if err := NormalizeKeyIPAuditFilter(&filter, time.Now().UTC()); err != nil {
		return nil, err
	}
	if filter.APIKeyID <= 0 {
		return nil, fmt.Errorf("%w: key_id is required", ErrKeyIPAuditInvalidFilter)
	}
	if err := validateKeyIPAuditPagination(ipPage, ipPageSize, "ip"); err != nil {
		return nil, err
	}
	if err := validateKeyIPAuditPagination(relatedPage, relatedPageSize, "related"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(relatedIP) != "" {
		var err error
		relatedIP, err = normalizeKeyIPAuditIP(relatedIP)
		if err != nil {
			return nil, err
		}
	}
	// A detail describes the whole key. IP is only a list eligibility filter;
	// carrying it into detail would hide the key's other risk signals.
	filter.IP = ""
	return s.repo.KeyDetail(ctx, filter, ipPage, ipPageSize, relatedIP, relatedPage, relatedPageSize)
}

func NormalizeKeyIPAuditFilter(filter *KeyIPAuditFilter, now time.Time) error {
	if filter == nil {
		return fmt.Errorf("%w: nil filter", ErrKeyIPAuditInvalidFilter)
	}
	now = now.UTC()
	if filter.EndTime.IsZero() {
		filter.EndTime = now
	}
	if filter.StartTime.IsZero() {
		filter.StartTime = filter.EndTime.Add(-KeyIPAuditDefaultRange)
	}
	filter.StartTime = filter.StartTime.UTC()
	filter.EndTime = filter.EndTime.UTC()
	if !filter.StartTime.Before(filter.EndTime) || filter.EndTime.Sub(filter.StartTime) > KeyIPAuditMaxRange {
		return fmt.Errorf("%w: time range must be positive and no longer than 30 days", ErrKeyIPAuditInvalidFilter)
	}
	if filter.EndTime.After(now.Add(2 * time.Minute)) {
		return fmt.Errorf("%w: end time cannot be far in the future", ErrKeyIPAuditInvalidFilter)
	}
	if filter.APIKeyID < 0 || filter.UserID < 0 {
		return fmt.Errorf("%w: ids must be positive", ErrKeyIPAuditInvalidFilter)
	}
	filter.KeyQuery = strings.TrimSpace(filter.KeyQuery)
	filter.UserQuery = strings.TrimSpace(filter.UserQuery)
	if len(filter.KeyQuery) > 200 || len(filter.UserQuery) > 200 {
		return fmt.Errorf("%w: text query is too long", ErrKeyIPAuditInvalidFilter)
	}
	if filter.Page < 1 {
		filter.Page = KeyIPAuditDefaultPage
	}
	if filter.PageSize < 1 {
		filter.PageSize = KeyIPAuditDefaultSize
	}
	if filter.PageSize > KeyIPAuditMaxPageSize {
		return fmt.Errorf("%w: page_size must be <= %d", ErrKeyIPAuditInvalidFilter, KeyIPAuditMaxPageSize)
	}
	if filter.IP != "" {
		var err error
		filter.IP, err = normalizeKeyIPAuditIP(filter.IP)
		if err != nil {
			return err
		}
	}
	filter.Risk = strings.ToLower(strings.TrimSpace(filter.Risk))
	if filter.Risk != "" && filter.Risk != "all" && filter.Risk != "none" && filter.Risk != "low" && filter.Risk != "medium" && filter.Risk != "high" {
		return fmt.Errorf("%w: risk must be none, low, medium, or high", ErrKeyIPAuditInvalidFilter)
	}
	filter.Status = strings.ToLower(strings.TrimSpace(filter.Status))
	if filter.Status == "all" {
		filter.Status = ""
	}
	if filter.Status != "" && !validKeyIPAuditKeyStatus(filter.Status) {
		return fmt.Errorf("%w: invalid key status", ErrKeyIPAuditInvalidFilter)
	}
	filter.Signal = strings.ToLower(strings.TrimSpace(filter.Signal))
	if filter.Signal != "" && filter.Signal != "all" && !validKeyIPAuditRiskCode(filter.Signal) {
		return fmt.Errorf("%w: invalid signal", ErrKeyIPAuditInvalidFilter)
	}
	if filter.Signal == "all" {
		filter.Signal = ""
	}
	return nil
}

func validateKeyIPAuditPagination(page, pageSize int, label string) error {
	if page < 1 || pageSize < 1 || pageSize > KeyIPAuditMaxPageSize {
		return fmt.Errorf("%w: invalid %s pagination", ErrKeyIPAuditInvalidFilter, label)
	}
	return nil
}

func normalizeKeyIPAuditIP(value string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return "", fmt.Errorf("%w: invalid ip", ErrKeyIPAuditInvalidFilter)
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String(), nil
	}
	return parsed.String(), nil
}

func validKeyIPAuditRiskCode(value string) bool {
	switch value {
	case "new_ip", "multi_ip_burst", "shared_ip_cross_users", "volume_spike":
		return true
	default:
		return false
	}
}

func validKeyIPAuditKeyStatus(value string) bool {
	if value == "inactive" {
		return true
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return value != ""
}

func normalizeTrustedCIDR(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: cidr is required", ErrKeyIPAuditInvalidFilter)
	}
	if !strings.Contains(value, "/") {
		ip, err := normalizeKeyIPAuditIP(value)
		if err != nil {
			return "", fmt.Errorf("%w: invalid cidr", ErrKeyIPAuditInvalidFilter)
		}
		if net.ParseIP(ip).To4() != nil {
			value = ip + "/32"
		} else {
			value = ip + "/128"
		}
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", fmt.Errorf("%w: invalid cidr", ErrKeyIPAuditInvalidFilter)
	}
	if v4 := ip.To4(); v4 != nil {
		ones, bits := network.Mask.Size()
		if bits == 128 {
			ones -= 96
		}
		if ones < 0 || ones > 32 {
			return "", fmt.Errorf("%w: invalid cidr", ErrKeyIPAuditInvalidFilter)
		}
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(ones, 32)), Mask: net.CIDRMask(ones, 32)}).String(), nil
	}
	return network.String(), nil
}

func (s *KeyIPAuditService) ListTrusted(ctx context.Context, apiKeyID, page, pageSize int64) ([]KeyIPAuditTrustedRule, int64, error) {
	if apiKeyID < 0 || page < 1 || pageSize < 1 || pageSize > int64(KeyIPAuditMaxPageSize) {
		return nil, 0, fmt.Errorf("%w: invalid trusted pagination", ErrKeyIPAuditInvalidFilter)
	}
	return s.repo.ListTrusted(ctx, apiKeyID, int(page), int(pageSize))
}

func (s *KeyIPAuditService) CreateTrusted(ctx context.Context, input KeyIPAuditTrustedInput) (*KeyIPAuditTrustedRule, error) {
	if input.APIKeyID <= 0 {
		return nil, fmt.Errorf("%w: key_id is required", ErrKeyIPAuditInvalidFilter)
	}
	cidr, err := normalizeTrustedCIDR(input.CIDR)
	if err != nil {
		return nil, err
	}
	if input.ExpiresAt != nil {
		v := input.ExpiresAt.UTC()
		input.ExpiresAt = &v
	}
	if s.apiKeyService != nil {
		if _, err := s.apiKeyService.GetByID(ctx, input.APIKeyID); err != nil {
			return nil, err
		}
	}
	input.CIDR = cidr
	input.Note = strings.TrimSpace(input.Note)
	if len(input.Note) > 500 {
		return nil, fmt.Errorf("%w: note is too long", ErrKeyIPAuditInvalidFilter)
	}
	return s.repo.CreateTrusted(ctx, input)
}

func (s *KeyIPAuditService) DeleteTrusted(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("%w: invalid trusted rule id", ErrKeyIPAuditInvalidFilter)
	}
	return s.repo.DeleteTrusted(ctx, id)
}

func (s *KeyIPAuditService) CreateDismissal(ctx context.Context, input KeyIPAuditDismissalInput) (*KeyIPAuditDismissal, error) {
	if input.APIKeyID <= 0 || strings.TrimSpace(input.IP) == "" {
		return nil, fmt.Errorf("%w: key_id and ip are required", ErrKeyIPAuditInvalidFilter)
	}
	input.RiskCode = strings.ToLower(strings.TrimSpace(input.RiskCode))
	if !validKeyIPAuditRiskCode(input.RiskCode) {
		return nil, fmt.Errorf("%w: invalid risk_code", ErrKeyIPAuditInvalidFilter)
	}
	var err error
	input.IP, err = normalizeKeyIPAuditIP(input.IP)
	if err != nil {
		return nil, err
	}
	input.EventStart = input.EventStart.UTC()
	input.EventEnd = input.EventEnd.UTC()
	now := time.Now().UTC()
	if input.EventStart.IsZero() || input.EventEnd.IsZero() || !input.EventStart.Before(input.EventEnd) || input.EventEnd.Sub(input.EventStart) > KeyIPAuditMaxRange || input.EventEnd.After(now.Add(2*time.Minute)) {
		return nil, fmt.Errorf("%w: dismissal event range must be past and no longer than 30 days", ErrKeyIPAuditInvalidFilter)
	}
	input.Note = strings.TrimSpace(input.Note)
	if len(input.Note) > 500 {
		return nil, fmt.Errorf("%w: note is too long", ErrKeyIPAuditInvalidFilter)
	}
	if s.apiKeyService != nil {
		if _, err := s.apiKeyService.GetByID(ctx, input.APIKeyID); err != nil {
			return nil, err
		}
	}
	return s.repo.CreateDismissal(ctx, input)
}

func (s *KeyIPAuditService) DeleteDismissal(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("%w: invalid dismissal id", ErrKeyIPAuditInvalidFilter)
	}
	return s.repo.DeleteDismissal(ctx, id)
}

// DisableKey and RotateKey deliberately use the existing API key service. This
// preserves its authorization, cache invalidation, and credential rotation.
func (s *KeyIPAuditService) DisableKey(ctx context.Context, id int64) (*APIKey, error) {
	if id <= 0 || s.apiKeyService == nil {
		return nil, fmt.Errorf("%w: invalid key id", ErrKeyIPAuditInvalidFilter)
	}
	status := StatusAPIKeyDisabled
	return s.apiKeyService.Update(ctx, id, 0, UpdateAPIKeyRequest{Status: &status})
}

func (s *KeyIPAuditService) RotateKey(ctx context.Context, id int64) (*APIKey, error) {
	if id <= 0 || s.apiKeyService == nil {
		return nil, fmt.Errorf("%w: invalid key id", ErrKeyIPAuditInvalidFilter)
	}
	return s.apiKeyService.RegenerateKey(ctx, id, 0)
}
