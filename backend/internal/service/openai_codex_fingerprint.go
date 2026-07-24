package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	codexFingerprintInboundContextKey = "codex_fingerprint_inbound_identity"
	codexFingerprintPersonaContextKey = "codex_fingerprint_persona"
	codexInstallationHeader           = "x-codex-installation-id"
	codexWindowHeader                 = "x-codex-window-id"
	codexTurnMetadataHeader           = "x-codex-turn-metadata"
	maxCodexFingerprintWorkspaceBytes = 64 * 1024
)

// CodexFingerprintPoolResolveRequest is the cache-level atomic allocation
// input. SourceHash is already HMAC-protected and never contains a raw client
// installation identifier.
type CodexFingerprintPoolResolveRequest struct {
	AccountID     int64
	SourceHash    string
	PoolSize      int
	IdleTimeout   time.Duration
	Now           time.Time
	WorkspaceJSON string
}

// CodexFingerprintPersona is the only fingerprint identity allowed to leave
// sub2api when pooling is enabled for an upstream account.
type CodexFingerprintPersona struct {
	InstallationID string
	WorkspaceJSON  string
	Slot           int
	Generation     int64
}

func (p CodexFingerprintPersona) WindowID() string {
	if p.InstallationID == "" {
		return ""
	}
	return hmacSHA256Hex("window", p.InstallationID)
}

type codexFingerprintInboundIdentity struct {
	InstallationID     string
	InstallationHeader string
	WorkspaceJSON      string
	UserAgent          string
	UserID             int64
	TurnMetadataHeader string
	WindowIDHeader     string
}

func (s *OpenAIGatewayService) applyCodexFingerprintPersona(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
) ([]byte, *CodexFingerprintPersona, error) {
	if account == nil {
		return body, nil, nil
	}
	if account.GetCodexFingerprintPoolSize() <= 0 || account.Platform != PlatformOpenAI {
		restoreCodexFingerprintInboundHeaders(c)
		return body, nil, nil
	}
	identity := captureCodexFingerprintInboundIdentity(ctx, c, body)
	persona, err := s.resolveCodexFingerprintPersona(ctx, account, identity)
	if err != nil {
		return nil, nil, err
	}
	rewritten, err := rewriteCodexFingerprintPayloadForContext(c, body, *persona)
	if err != nil {
		return nil, nil, err
	}
	if c != nil && c.Request != nil {
		if err := rewriteCodexFingerprintHeaders(c.Request.Header, *persona, ""); err != nil {
			return nil, nil, err
		}
		c.Set(codexFingerprintPersonaContextKey, *persona)
	}
	return rewritten, persona, nil
}

func (s *OpenAIGatewayService) resolveCodexFingerprintPersona(
	ctx context.Context,
	account *Account,
	identity codexFingerprintInboundIdentity,
) (*CodexFingerprintPersona, error) {
	if s == nil || s.cfg == nil || strings.TrimSpace(s.cfg.JWT.Secret) == "" {
		return nil, errors.New("codex fingerprint pool requires a configured server secret")
	}
	cache, ok := s.cache.(CodexFingerprintPoolCache)
	if !ok || cache == nil {
		return nil, errors.New("codex fingerprint pool cache is unavailable")
	}

	sourceMaterial := strings.TrimSpace(identity.InstallationID)
	if sourceMaterial != "" {
		sourceMaterial = "installation:" + sourceMaterial
	} else if identity.WorkspaceJSON != "" {
		sum := sha256.Sum256([]byte(identity.WorkspaceJSON))
		sourceMaterial = "workspace:" + hex.EncodeToString(sum[:])
	} else if normalizedUA := normalizeCodexFingerprintUserAgent(identity.UserAgent); normalizedUA != "" {
		sourceMaterial = "user-agent:" + normalizedUA
	} else {
		sourceMaterial = "unknown-codex-client"
	}
	sourceInput := strconv.FormatInt(account.ID, 10) + ":" + strconv.FormatInt(identity.UserID, 10) + ":" + sourceMaterial
	sourceHash := hmacSHA256Hex(sourceInput, s.cfg.JWT.Secret)

	persona, err := cache.ResolveCodexFingerprintPersona(ctx, CodexFingerprintPoolResolveRequest{
		AccountID:     account.ID,
		SourceHash:    sourceHash,
		PoolSize:      account.GetCodexFingerprintPoolSize(),
		IdleTimeout:   time.Duration(account.GetCodexFingerprintIdleTimeoutDays()) * 24 * time.Hour,
		Now:           time.Now(),
		WorkspaceJSON: identity.WorkspaceJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve account %d codex fingerprint persona: %w", account.ID, err)
	}
	return &persona, nil
}

func captureCodexFingerprintInboundIdentity(ctx context.Context, c *gin.Context, body []byte) codexFingerprintInboundIdentity {
	if c != nil {
		if cached, ok := c.Get(codexFingerprintInboundContextKey); ok {
			if identity, valid := cached.(codexFingerprintInboundIdentity); valid {
				return identity
			}
		}
	}

	identity := codexFingerprintInboundIdentity{}
	if c != nil && c.Request != nil {
		identity.InstallationHeader = c.Request.Header.Get(codexInstallationHeader)
		identity.InstallationID = strings.TrimSpace(identity.InstallationHeader)
		identity.UserAgent = c.Request.Header.Get("user-agent")
		identity.TurnMetadataHeader = c.Request.Header.Get(codexTurnMetadataHeader)
		identity.WindowIDHeader = c.Request.Header.Get(codexWindowHeader)
		if metadata := strings.TrimSpace(identity.TurnMetadataHeader); metadata != "" {
			installationID, workspaceJSON := codexFingerprintValuesFromTurnMetadata(metadata)
			if identity.InstallationID == "" {
				identity.InstallationID = installationID
			}
			identity.WorkspaceJSON = workspaceJSON
		}
	}
	if ctx != nil {
		identity.UserID, _ = ctx.Value(ctxkey.UserID).(int64)
	}
	if identity.UserID <= 0 && c != nil && c.Request != nil {
		identity.UserID, _ = c.Request.Context().Value(ctxkey.UserID).(int64)
	}

	if len(body) > 0 && gjson.ValidBytes(body) {
		if identity.InstallationID == "" {
			for _, path := range []string{
				"client_metadata.x-codex-installation-id",
				"client_metadata.installation_id",
			} {
				if value := strings.TrimSpace(gjson.GetBytes(body, path).String()); value != "" {
					identity.InstallationID = value
					break
				}
			}
		}
		if metadataResult := gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata"); metadataResult.Exists() {
			metadata := metadataResult.String()
			if metadataResult.Type == gjson.JSON {
				metadata = metadataResult.Raw
			}
			installationID, workspaceJSON := codexFingerprintValuesFromTurnMetadata(metadata)
			if identity.InstallationID == "" {
				identity.InstallationID = installationID
			}
			if identity.WorkspaceJSON == "" {
				identity.WorkspaceJSON = workspaceJSON
			}
		}
	}
	identity.WorkspaceJSON = canonicalCodexWorkspaceJSON(identity.WorkspaceJSON)
	if c != nil {
		c.Set(codexFingerprintInboundContextKey, identity)
	}
	return identity
}

func restoreCodexFingerprintInboundHeaders(c *gin.Context) {
	if c == nil || c.Request == nil {
		return
	}
	cached, ok := c.Get(codexFingerprintInboundContextKey)
	if !ok {
		return
	}
	identity, ok := cached.(codexFingerprintInboundIdentity)
	if !ok {
		return
	}
	setOrDeleteHeader(c.Request.Header, codexInstallationHeader, identity.InstallationHeader)
	setOrDeleteHeader(c.Request.Header, codexWindowHeader, identity.WindowIDHeader)
	setOrDeleteHeader(c.Request.Header, codexTurnMetadataHeader, identity.TurnMetadataHeader)
	c.Set(codexFingerprintPersonaContextKey, nil)
}

func setOrDeleteHeader(headers http.Header, name, value string) {
	if value == "" {
		headers.Del(name)
		return
	}
	headers.Set(name, value)
}

func codexFingerprintValuesFromTurnMetadata(raw string) (string, string) {
	var metadata map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &metadata) != nil {
		return "", ""
	}
	installationID, _ := metadata["installation_id"].(string)
	return strings.TrimSpace(installationID), canonicalCodexWorkspaceJSON(extractWorkspacesJSON(metadata))
}

func canonicalCodexWorkspaceJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxCodexFingerprintWorkspaceBytes {
		return ""
	}
	var workspace any
	if json.Unmarshal([]byte(raw), &workspace) != nil {
		return ""
	}
	canonical, err := json.Marshal(workspace)
	if err != nil || len(canonical) > maxCodexFingerprintWorkspaceBytes {
		return ""
	}
	return string(canonical)
}

func normalizeCodexFingerprintUserAgent(raw string) string {
	return strings.ToLower(strings.Join(strings.Fields(raw), " "))
}

func rewriteCodexFingerprintPayload(body []byte, persona CodexFingerprintPersona) ([]byte, error) {
	if persona.InstallationID == "" {
		return nil, errors.New("codex fingerprint persona has an empty installation id")
	}
	if len(body) == 0 {
		return body, nil
	}
	if !gjson.ValidBytes(body) {
		return nil, errors.New("cannot apply codex fingerprint persona to invalid JSON")
	}

	rewritten := body
	var err error
	for _, path := range []string{
		"client_metadata.x-codex-installation-id",
		"client_metadata.installation_id",
	} {
		rewritten, err = sjson.SetBytes(rewritten, path, persona.InstallationID)
		if err != nil {
			return nil, fmt.Errorf("rewrite %s: %w", path, err)
		}
	}

	metadataResult := gjson.GetBytes(rewritten, "client_metadata.x-codex-turn-metadata")
	if metadataResult.Exists() {
		metadata := metadataResult.String()
		metadataWasObject := metadataResult.Type == gjson.JSON
		if metadataWasObject {
			metadata = metadataResult.Raw
		}
		metadata, err = rewriteCodexTurnMetadata(metadata, persona, "")
		if err != nil {
			return nil, fmt.Errorf("rewrite body codex turn metadata: %w", err)
		}
		if metadataWasObject {
			var object any
			if err := json.Unmarshal([]byte(metadata), &object); err != nil {
				return nil, err
			}
			rewritten, err = sjson.SetBytes(rewritten, "client_metadata.x-codex-turn-metadata", object)
		} else {
			rewritten, err = sjson.SetBytes(rewritten, "client_metadata.x-codex-turn-metadata", metadata)
		}
		if err != nil {
			return nil, fmt.Errorf("write body codex turn metadata: %w", err)
		}
	}
	return rewritten, nil
}

func rewriteCodexFingerprintPayloadForContext(c *gin.Context, body []byte, persona CodexFingerprintPersona) ([]byte, error) {
	rewritten, err := rewriteCodexFingerprintPayload(body, persona)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return rewritten, nil
	}
	if cached, exists := c.Get(codexFingerprintInboundContextKey); exists {
		if identity, valid := cached.(codexFingerprintInboundIdentity); valid {
			if rawID := strings.TrimSpace(identity.InstallationID); rawID != "" && bytes.Contains(rewritten, []byte(rawID)) {
				return nil, errors.New("raw Codex installation id remains in rewritten payload")
			}
		}
	}
	return rewritten, nil
}

func rewriteCodexFingerprintHeaders(headers http.Header, persona CodexFingerprintPersona, isolatedSessionID string) error {
	if headers == nil {
		return nil
	}
	headers.Set(codexInstallationHeader, persona.InstallationID)
	headers.Set(codexWindowHeader, persona.WindowID())
	if raw := strings.TrimSpace(headers.Get(codexTurnMetadataHeader)); raw != "" {
		rewritten, err := rewriteCodexTurnMetadata(raw, persona, isolatedSessionID)
		if err != nil {
			return fmt.Errorf("rewrite codex turn metadata header: %w", err)
		}
		headers.Set(codexTurnMetadataHeader, rewritten)
	}
	return nil
}

func rewriteCodexTurnMetadata(raw string, persona CodexFingerprintPersona, isolatedSessionID string) (string, error) {
	var metadata map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &metadata); err != nil {
		return "", err
	}
	metadata["installation_id"] = persona.InstallationID
	metadata["window_id"] = persona.WindowID()
	if isolatedSessionID != "" {
		metadata["session_id"] = isolatedSessionID
	}
	if persona.WorkspaceJSON == "" {
		delete(metadata, "workspaces")
	} else {
		var workspace any
		if err := json.Unmarshal([]byte(persona.WorkspaceJSON), &workspace); err != nil {
			return "", fmt.Errorf("decode persona workspace: %w", err)
		}
		metadata["workspaces"] = workspace
	}
	rewritten, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return string(rewritten), nil
}

func codexFingerprintPersonaFromContext(c *gin.Context) (*CodexFingerprintPersona, bool) {
	if c == nil {
		return nil, false
	}
	value, ok := c.Get(codexFingerprintPersonaContextKey)
	if !ok {
		return nil, false
	}
	persona, ok := value.(CodexFingerprintPersona)
	return &persona, ok
}

func enforceCodexFingerprintPersonaHeaders(c *gin.Context, headers http.Header) error {
	persona, ok := codexFingerprintPersonaFromContext(c)
	if !ok {
		return nil
	}
	if err := rewriteCodexFingerprintHeaders(headers, *persona, headers.Get("session_id")); err != nil {
		return err
	}
	if cached, exists := c.Get(codexFingerprintInboundContextKey); exists {
		if identity, valid := cached.(codexFingerprintInboundIdentity); valid {
			rawID := strings.TrimSpace(identity.InstallationID)
			if rawID != "" {
				for _, values := range headers {
					for _, value := range values {
						if strings.Contains(value, rawID) {
							return errors.New("raw Codex installation id remains in rewritten headers")
						}
					}
				}
			}
		}
	}
	return nil
}

func hmacSHA256Hex(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
