package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

const (
	keyIPAuditActionDisableKey      = "admin.key_ip_audit.keys.disable"
	keyIPAuditActionRotateKey       = "admin.key_ip_audit.keys.rotate"
	keyIPAuditActionCreateTrusted   = "admin.key_ip_audit.trusted.create"
	keyIPAuditActionDeleteTrusted   = "admin.key_ip_audit.trusted.delete"
	keyIPAuditActionCreateDismissal = "admin.key_ip_audit.dismissals.create"
	keyIPAuditActionDeleteDismissal = "admin.key_ip_audit.dismissals.delete"
)

// KeyIPAuditHandler exposes the administrator-only key/IP audit contract.
// The service owns all aggregation and disposition rules; this handler only
// translates HTTP input and keeps credentials out of the audit context.
type KeyIPAuditHandler struct {
	service       *service.KeyIPAuditService
	apiKeyService *service.APIKeyService
}

func NewKeyIPAuditHandler(auditService *service.KeyIPAuditService, apiKeyService *service.APIKeyService) *KeyIPAuditHandler {
	return &KeyIPAuditHandler{service: auditService, apiKeyService: apiKeyService}
}

// ListKeys handles GET /api/v1/admin/key-ip-audit/keys.
func (h *KeyIPAuditHandler) ListKeys(c *gin.Context) {
	filter, err := parseKeyIPAuditFilter(c)
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return
	}

	result, err := h.service.ListKeys(c.Request.Context(), filter)
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, result)
}

// KeyDetail handles GET /api/v1/admin/key-ip-audit/keys/:id.
func (h *KeyIPAuditHandler) KeyDetail(c *gin.Context) {
	keyID, err := parsePositiveID(c.Param("id"))
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return
	}
	filter, err := parseKeyIPAuditFilter(c)
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return
	}
	filter.APIKeyID = keyID
	ipPage, ipPageSize, relatedPage, relatedPageSize, relatedIP, err := parseKeyIPAuditDetailQuery(c)
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return
	}

	result, err := h.service.KeyDetail(c.Request.Context(), filter, ipPage, ipPageSize, relatedIP, relatedPage, relatedPageSize)
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, result)
}

// DisableKey handles POST /api/v1/admin/key-ip-audit/keys/:id/disable.
func (h *KeyIPAuditHandler) DisableKey(c *gin.Context) {
	keyID, ok := h.parseEmptyBodyKey(c, keyIPAuditActionDisableKey)
	if !ok {
		return
	}

	key, err := h.service.DisableKey(c.Request.Context(), keyID)
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, gin.H{"key_id": keyID, "key_status": key.Status})
}

// RotateKey handles POST /api/v1/admin/key-ip-audit/keys/:id/rotate.
func (h *KeyIPAuditHandler) RotateKey(c *gin.Context) {
	keyID, ok := h.parseEmptyBodyKey(c, keyIPAuditActionRotateKey)
	if !ok {
		return
	}
	c.Header("Cache-Control", "private, no-store")

	// Only the key ID and a one-way fingerprint are handed to the coordinator.
	// The generated credential is re-read from the API key service after the
	// idempotent operation, so no secret copy is persisted or kept in process.
	result, err := executeAdminIdempotent(c, "admin.key_ip_audit.keys.rotate", struct {
		KeyID int64 `json:"key_id"`
	}{KeyID: keyID}, service.DefaultWriteIdempotencyTTL(), func(ctx context.Context) (any, error) {
		key, rotateErr := h.service.RotateKey(ctx, keyID)
		if rotateErr != nil {
			return nil, rotateErr
		}
		if key == nil || key.Key == "" {
			return nil, errors.New("rotated key secret unavailable")
		}
		return rotateStoredResult{
			KeyID:                keyID,
			CredentialFingerprint: fingerprintAPIKeyCredential(key.Key),
		}, nil
	})
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	fingerprint, ok := rotateCredentialFingerprint(result, keyID)
	if !ok {
		response.Error(c, http.StatusConflict, "Rotated secret is no longer available; retry with a new Idempotency-Key")
		return
	}
	if h.apiKeyService == nil {
		response.InternalError(c, "Internal server error")
		return
	}
	key, err := h.apiKeyService.GetByID(c.Request.Context(), keyID)
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	if key == nil || key.Key == "" || subtle.ConstantTimeCompare([]byte(fingerprintAPIKeyCredential(key.Key)), []byte(fingerprint)) != 1 {
		response.Error(c, http.StatusConflict, "Rotated secret is no longer available; retry with a new Idempotency-Key")
		return
	}
	if result != nil && result.Replayed {
		c.Header("X-Idempotency-Replayed", "true")
	}
	response.Success(c, gin.H{"key_id": keyID, "secret": key.Key})
}

// ListTrusted handles GET /api/v1/admin/key-ip-audit/trusted.
func (h *KeyIPAuditHandler) ListTrusted(c *gin.Context) {
	keyID, page, pageSize, err := parseTrustedQuery(c)
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return
	}
	items, total, err := h.service.ListTrusted(c.Request.Context(), keyID, int64(page), int64(pageSize))
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, gin.H{"items": items, "total": total})
}

type createTrustedRequest struct {
	KeyID     int64      `json:"key_id"`
	CIDR      string     `json:"cidr"`
	Note      string     `json:"note"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (h *KeyIPAuditHandler) CreateTrusted(c *gin.Context) {
	var req createTrustedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		setKeyIPAuditAction(c, keyIPAuditActionCreateTrusted, nil)
		writeKeyIPAuditBadRequest(c)
		return
	}
	setKeyIPAuditAction(c, keyIPAuditActionCreateTrusted, map[string]any{
		"key_id": req.KeyID,
		"cidr":   strings.TrimSpace(req.CIDR),
	})
	if req.KeyID <= 0 || strings.TrimSpace(req.CIDR) == "" {
		writeKeyIPAuditBadRequest(c)
		return
	}

	input := service.KeyIPAuditTrustedInput{
		APIKeyID:  req.KeyID,
		CIDR:      req.CIDR,
		Note:      req.Note,
		ExpiresAt: req.ExpiresAt,
		CreatedBy: keyIPAuditActorID(c),
	}
	result, err := h.service.CreateTrusted(c.Request.Context(), input)
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, result)
}

// DeleteTrusted handles DELETE /api/v1/admin/key-ip-audit/trusted/:id.
func (h *KeyIPAuditHandler) DeleteTrusted(c *gin.Context) {
	ruleID, err := parsePositiveID(c.Param("id"))
	setKeyIPAuditAction(c, keyIPAuditActionDeleteTrusted, map[string]any{"rule_id": c.Param("id")})
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return
	}
	if err := h.service.DeleteTrusted(c.Request.Context(), ruleID); err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, gin.H{})
}

type createDismissalRequest struct {
	KeyID      int64      `json:"key_id"`
	IP         string     `json:"ip"`
	RiskCode   string     `json:"risk_code"`
	EventStart *time.Time `json:"event_start"`
	EventEnd   *time.Time `json:"event_end"`
	Note       string     `json:"note"`
}

// CreateDismissal handles POST /api/v1/admin/key-ip-audit/dismissals.
func (h *KeyIPAuditHandler) CreateDismissal(c *gin.Context) {
	var req createDismissalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		setKeyIPAuditAction(c, keyIPAuditActionCreateDismissal, nil)
		writeKeyIPAuditBadRequest(c)
		return
	}
	setKeyIPAuditAction(c, keyIPAuditActionCreateDismissal, map[string]any{
		"key_id":    req.KeyID,
		"ip":        normalizeAuditIPForExtra(req.IP),
		"risk_code": strings.ToLower(strings.TrimSpace(req.RiskCode)),
	})
	if req.KeyID <= 0 || req.EventStart == nil || req.EventEnd == nil || req.EventEnd.After(time.Now().UTC()) {
		writeKeyIPAuditBadRequest(c)
		return
	}

	input := service.KeyIPAuditDismissalInput{
		APIKeyID:   req.KeyID,
		IP:         req.IP,
		RiskCode:   req.RiskCode,
		EventStart: *req.EventStart,
		EventEnd:   *req.EventEnd,
		Note:       req.Note,
		CreatedBy:  keyIPAuditActorID(c),
	}
	result, err := h.service.CreateDismissal(c.Request.Context(), input)
	if err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, result)
}

// DeleteDismissal handles DELETE /api/v1/admin/key-ip-audit/dismissals/:id.
func (h *KeyIPAuditHandler) DeleteDismissal(c *gin.Context) {
	dismissalID, err := parsePositiveID(c.Param("id"))
	setKeyIPAuditAction(c, keyIPAuditActionDeleteDismissal, map[string]any{"dismissal_id": c.Param("id")})
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return
	}
	if err := h.service.DeleteDismissal(c.Request.Context(), dismissalID); err != nil {
		writeKeyIPAuditError(c, err)
		return
	}
	response.Success(c, gin.H{})
}

func (h *KeyIPAuditHandler) parseEmptyBodyKey(c *gin.Context, action string) (int64, bool) {
	keyID, err := parsePositiveID(c.Param("id"))
	setKeyIPAuditAction(c, action, map[string]any{"key_id": c.Param("id")})
	if err != nil {
		writeKeyIPAuditBadRequest(c)
		return 0, false
	}

	var body map[string]json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil || body == nil || len(body) != 0 {
		writeKeyIPAuditBadRequest(c)
		return 0, false
	}
	return keyID, true
}

func parseKeyIPAuditFilter(c *gin.Context) (service.KeyIPAuditFilter, error) {
	page, err := parsePositivePage(c.Query("page"), service.KeyIPAuditDefaultPage)
	if err != nil {
		return service.KeyIPAuditFilter{}, err
	}
	pageSize, err := parsePositivePage(c.Query("page_size"), service.KeyIPAuditDefaultSize)
	if err != nil || pageSize > service.KeyIPAuditMaxPageSize {
		return service.KeyIPAuditFilter{}, fmt.Errorf("invalid page_size")
	}

	filter := service.KeyIPAuditFilter{Page: page, PageSize: pageSize}
	if value := strings.TrimSpace(c.Query("from")); value != "" {
		filter.StartTime, err = parseRFC3339(value)
		if err != nil {
			return service.KeyIPAuditFilter{}, err
		}
	}
	if value := strings.TrimSpace(c.Query("to")); value != "" {
		filter.EndTime, err = parseRFC3339(value)
		if err != nil {
			return service.KeyIPAuditFilter{}, err
		}
	}
	if value := strings.TrimSpace(c.Query("key_id")); value != "" {
		filter.APIKeyID, err = parsePositiveID(value)
		if err != nil {
			return service.KeyIPAuditFilter{}, err
		}
	}
	if value := strings.TrimSpace(c.Query("user_id")); value != "" {
		filter.UserID, err = parsePositiveID(value)
		if err != nil {
			return service.KeyIPAuditFilter{}, err
		}
	}
	filter.KeyQuery = strings.TrimSpace(c.Query("key"))
	filter.UserQuery = strings.TrimSpace(c.Query("user"))
	filter.IP = strings.TrimSpace(c.Query("ip"))
	filter.Risk = strings.ToLower(strings.TrimSpace(c.Query("risk")))
	filter.Status = strings.ToLower(strings.TrimSpace(c.Query("status")))
	filter.Signal = strings.ToLower(strings.TrimSpace(c.Query("signal")))
	if len(filter.KeyQuery) > 200 || len(filter.UserQuery) > 200 {
		return service.KeyIPAuditFilter{}, fmt.Errorf("text query too long")
	}
	if filter.Risk == "all" || filter.Signal == "all" || filter.Status == "all" {
		return service.KeyIPAuditFilter{}, fmt.Errorf("all is not a valid explicit filter")
	}
	return filter, nil
}

func parseKeyIPAuditDetailQuery(c *gin.Context) (ipPage, ipPageSize, relatedPage, relatedPageSize int, relatedIP string, err error) {
	ipPage, err = parsePositivePage(c.Query("ip_page"), service.KeyIPAuditDefaultPage)
	if err != nil {
		return 0, 0, 0, 0, "", err
	}
	ipPageSize, err = parsePositivePage(c.Query("ip_page_size"), service.KeyIPAuditDefaultSize)
	if err != nil || ipPageSize > service.KeyIPAuditMaxPageSize {
		return 0, 0, 0, 0, "", fmt.Errorf("invalid ip_page_size")
	}
	relatedPage, err = parsePositivePage(c.Query("related_page"), service.KeyIPAuditDefaultPage)
	if err != nil {
		return 0, 0, 0, 0, "", err
	}
	relatedPageSize, err = parsePositivePage(c.Query("related_page_size"), service.KeyIPAuditDefaultSize)
	if err != nil || relatedPageSize > service.KeyIPAuditMaxPageSize {
		return 0, 0, 0, 0, "", fmt.Errorf("invalid related_page_size")
	}
	if value := strings.TrimSpace(c.Query("related_ip")); value != "" {
		relatedIP, err = normalizeAuditIP(value)
		if err != nil {
			return 0, 0, 0, 0, "", err
		}
	}
	return ipPage, ipPageSize, relatedPage, relatedPageSize, relatedIP, nil
}

func parseTrustedQuery(c *gin.Context) (keyID int64, page, pageSize int, err error) {
	page, err = parsePositivePage(c.Query("page"), service.KeyIPAuditDefaultPage)
	if err != nil {
		return 0, 0, 0, err
	}
	pageSize, err = parsePositivePage(c.Query("page_size"), service.KeyIPAuditDefaultSize)
	if err != nil || pageSize > service.KeyIPAuditMaxPageSize {
		return 0, 0, 0, fmt.Errorf("invalid page_size")
	}
	if value := strings.TrimSpace(c.Query("key_id")); value != "" {
		keyID, err = parsePositiveID(value)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	return keyID, page, pageSize, nil
}

func parsePositivePage(value string, fallback int) (int, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("invalid pagination")
	}
	return parsed, nil
}

func parsePositiveID(value string) (int64, error) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("invalid id")
	}
	return parsed, nil
}

func parseRFC3339(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time")
	}
	return parsed.UTC(), nil
}

func normalizeAuditIP(value string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return "", fmt.Errorf("invalid ip")
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String(), nil
	}
	return parsed.String(), nil
}

func normalizeAuditIPForExtra(value string) string {
	parsed, err := normalizeAuditIP(value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return parsed
}

func setKeyIPAuditAction(c *gin.Context, action string, extra map[string]any) {
	servermiddleware.SetAuditAction(c, action)
	if len(extra) == 0 {
		return
	}
	// The existing middleware copies this controlled scalar map into audit_logs.
	// Only IDs, IPs, CIDRs and signal names are supplied here; credentials and
	// request/response bodies never enter this map.
	c.Set("audit_extra", extra)
}

type rotateStoredResult struct {
	KeyID                int64  `json:"key_id"`
	CredentialFingerprint string `json:"credential_fingerprint"`
}

func fingerprintAPIKeyCredential(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func rotateCredentialFingerprint(result *service.IdempotencyExecuteResult, expectedKeyID int64) (string, bool) {
	if expectedKeyID <= 0 {
		return "", false
	}
	if result == nil || result.Data == nil {
		return "", false
	}
	switch value := result.Data.(type) {
	case rotateStoredResult:
		return value.CredentialFingerprint, value.KeyID == expectedKeyID && value.CredentialFingerprint != ""
	case map[string]any:
		keyID, ok := storedKeyID(value["key_id"])
		if !ok || keyID != expectedKeyID {
			return "", false
		}
		fingerprint, ok := value["credential_fingerprint"].(string)
		return fingerprint, ok && fingerprint != ""
	default:
		return "", false
	}
}

func storedKeyID(value any) (int64, bool) {
	switch id := value.(type) {
	case int64:
		return id, id > 0
	case int:
		return int64(id), id > 0
	case float64:
		if id != float64(int64(id)) {
			return 0, false
		}
		return int64(id), id > 0
	case json.Number:
		parsed, err := id.Int64()
		return parsed, err == nil && parsed > 0
	default:
		return 0, false
	}
}

func keyIPAuditActorID(c *gin.Context) *int64 {
	subject, ok := servermiddleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		return nil
	}
	uid := subject.UserID
	return &uid
}

func writeKeyIPAuditBadRequest(c *gin.Context) {
	response.BadRequest(c, "Invalid key/IP audit request")
}

func writeKeyIPAuditError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, service.ErrKeyIPAuditInvalidFilter) {
		writeKeyIPAuditBadRequest(c)
		return
	}
	if errors.Is(err, service.ErrKeyIPAuditTrustedNotFound) || errors.Is(err, service.ErrKeyIPAuditDismissalNotFound) {
		response.NotFound(c, "Key/IP audit disposition not found")
		return
	}
	if status, _ := infraerrors.ToHTTP(err); status != http.StatusOK {
		response.ErrorFrom(c, err)
		return
	}
	// Repository errors are deliberately collapsed so SQL details never reach
	// an administrator-facing response.
	response.InternalError(c, "Internal server error")
}
