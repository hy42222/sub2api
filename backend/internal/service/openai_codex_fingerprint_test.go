package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type codexFingerprintGatewayCacheStub struct {
	request CodexFingerprintPoolResolveRequest
	persona CodexFingerprintPersona
	err     error
}

func (s *codexFingerprintGatewayCacheStub) GetSessionAccountID(context.Context, int64, string) (int64, error) {
	return 0, nil
}

func (s *codexFingerprintGatewayCacheStub) SetSessionAccountID(context.Context, int64, string, int64, time.Duration) error {
	return nil
}

func (s *codexFingerprintGatewayCacheStub) RefreshSessionTTL(context.Context, int64, string, time.Duration) error {
	return nil
}

func (s *codexFingerprintGatewayCacheStub) DeleteSessionAccountID(context.Context, int64, string) error {
	return nil
}

func (s *codexFingerprintGatewayCacheStub) ResolveCodexFingerprintPersona(_ context.Context, request CodexFingerprintPoolResolveRequest) (CodexFingerprintPersona, error) {
	s.request = request
	return s.persona, s.err
}

func TestRewriteCodexFingerprintPayloadAndHeaders(t *testing.T) {
	const rawInstallationID = "real-client-installation-id"
	body := []byte(`{
		"model":"gpt-5-codex",
		"client_metadata":{
			"x-codex-installation-id":"real-client-installation-id",
			"installation_id":"another-real-id",
			"x-codex-turn-metadata":"{\"installation_id\":\"real-client-installation-id\",\"window_id\":\"real-window\",\"workspaces\":{\"real\":{\"latest_git_commit_hash\":\"secret\"}}}"
		}
	}`)
	persona := CodexFingerprintPersona{
		InstallationID: "5f48875e-5059-4451-bd72-8b8cc642a59a",
		WorkspaceJSON:  `{"pooled":{"latest_git_commit_hash":"pooled-commit"}}`,
		Slot:           1,
		Generation:     4,
	}

	rewritten, err := rewriteCodexFingerprintPayload(body, persona)
	require.NoError(t, err)
	require.NotContains(t, string(rewritten), rawInstallationID)
	require.NotContains(t, string(rewritten), "another-real-id")
	require.Equal(t, persona.InstallationID, gjson.GetBytes(rewritten, "client_metadata.x-codex-installation-id").String())
	require.Equal(t, persona.InstallationID, gjson.GetBytes(rewritten, "client_metadata.installation_id").String())

	metadataRaw := gjson.GetBytes(rewritten, "client_metadata.x-codex-turn-metadata").String()
	require.Equal(t, persona.InstallationID, gjson.Get(metadataRaw, "installation_id").String())
	require.Equal(t, persona.WindowID(), gjson.Get(metadataRaw, "window_id").String())
	require.Equal(t, "pooled-commit", gjson.Get(metadataRaw, "workspaces.pooled.latest_git_commit_hash").String())
	require.NotContains(t, metadataRaw, "secret")

	headers := make(http.Header)
	headers.Set(codexInstallationHeader, rawInstallationID)
	headers.Set(codexWindowHeader, "real-window")
	headers.Set(codexTurnMetadataHeader, `{"installation_id":"real-client-installation-id","session_id":"old"}`)
	require.NoError(t, rewriteCodexFingerprintHeaders(headers, persona, "isolated-session"))
	require.Equal(t, persona.InstallationID, headers.Get(codexInstallationHeader))
	require.Equal(t, persona.WindowID(), headers.Get(codexWindowHeader))
	require.False(t, strings.Contains(headers.Get(codexTurnMetadataHeader), rawInstallationID))
	require.Equal(t, "isolated-session", gjson.Get(headers.Get(codexTurnMetadataHeader), "session_id").String())
}

func TestRewriteCodexFingerprintPayloadDropsWorkspaceWhenPersonaHasNone(t *testing.T) {
	body := []byte(`{"client_metadata":{"x-codex-turn-metadata":{"installation_id":"raw","workspaces":{"raw":{}}}}}`)
	persona := CodexFingerprintPersona{InstallationID: "7c181bd4-0307-4b90-b933-3d9be6f8694f"}

	rewritten, err := rewriteCodexFingerprintPayload(body, persona)
	require.NoError(t, err)
	require.Equal(t, persona.InstallationID, gjson.GetBytes(rewritten, "client_metadata.x-codex-turn-metadata.installation_id").String())
	require.False(t, gjson.GetBytes(rewritten, "client_metadata.x-codex-turn-metadata.workspaces").Exists())
}

func TestApplyCodexFingerprintPersonaHashesSourceAndFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const rawID = "real-installation-id-must-not-reach-cache"
	body := []byte(`{"model":"gpt-5-codex","client_metadata":{"x-codex-installation-id":"` + rawID + `"}}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	request.Header.Set(codexInstallationHeader, rawID)
	request = request.WithContext(context.WithValue(request.Context(), ctxkey.UserID, int64(81)))
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = request
	account := &Account{
		ID:       9,
		Platform: PlatformOpenAI,
		Extra: map[string]any{
			"codex_fingerprint_pool_size":         2,
			"codex_fingerprint_idle_timeout_days": 45,
		},
	}

	cache := &codexFingerprintGatewayCacheStub{persona: CodexFingerprintPersona{
		InstallationID: "e790aef4-a428-4df9-8874-4aaec3af3b46",
		WorkspaceJSON:  `{}`,
	}}
	service := &OpenAIGatewayService{
		cache: cache,
		cfg:   &config.Config{JWT: config.JWTConfig{Secret: "server-secret"}},
	}
	rewritten, persona, err := service.applyCodexFingerprintPersona(request.Context(), c, account, body)
	require.NoError(t, err)
	require.NotNil(t, persona)
	require.NotContains(t, cache.request.SourceHash, rawID)
	require.Len(t, cache.request.SourceHash, sha256.Size*2)
	require.Equal(t, 2, cache.request.PoolSize)
	require.Equal(t, 45*24*time.Hour, cache.request.IdleTimeout)
	require.NotContains(t, string(rewritten), rawID)
	require.Equal(t, persona.InstallationID, c.Request.Header.Get(codexInstallationHeader))
	disabledAccount := *account
	disabledAccount.Extra = nil
	restoredBody, disabledPersona, err := service.applyCodexFingerprintPersona(request.Context(), c, &disabledAccount, body)
	require.NoError(t, err)
	require.Nil(t, disabledPersona)
	require.Equal(t, body, restoredBody)
	require.Equal(t, rawID, c.Request.Header.Get(codexInstallationHeader))

	failingCache := &codexFingerprintGatewayCacheStub{err: errors.New("redis unavailable")}
	failingService := &OpenAIGatewayService{
		cache: failingCache,
		cfg:   &config.Config{JWT: config.JWTConfig{Secret: "server-secret"}},
	}
	failingRequest := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	failingRequest.Header.Set(codexInstallationHeader, rawID)
	failingContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	failingContext.Request = failingRequest
	rewritten, persona, err = failingService.applyCodexFingerprintPersona(failingRequest.Context(), failingContext, account, body)
	require.Error(t, err)
	require.Nil(t, rewritten)
	require.Nil(t, persona)
	require.Equal(t, rawID, failingContext.Request.Header.Get(codexInstallationHeader))
}
