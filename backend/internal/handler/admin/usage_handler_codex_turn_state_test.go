package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type codexTurnStateUsageRepoStub struct {
	service.UsageLogRepository
	record *service.UsageLog
	err    error
}

func (s *codexTurnStateUsageRepoStub) GetByID(context.Context, int64) (*service.UsageLog, error) {
	return s.record, s.err
}

func newCodexTurnStateHandlerRouter(repo service.UsageLogRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	handler := NewUsageHandler(service.NewUsageService(repo, nil, nil, nil), nil, nil, nil)
	router := gin.New()
	router.GET("/api/v1/admin/usage/:id/codex-turn-state", handler.GetCodexTurnState)
	router.GET("/api/v1/admin/usage", handler.List)
	return router
}

func TestAdminUsageCodexTurnStateDetail(t *testing.T) {
	state := "turn-state-secret"
	repo := &codexTurnStateUsageRepoStub{record: &service.UsageLog{ID: 7, CodexTurnState: &state}}
	router := newCodexTurnStateHandlerRouter(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/7/codex-turn-state", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var body struct {
		Data dto.AdminCodexTurnState `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, state, body.Data.CodexTurnState)
	require.Equal(t, len(state), body.Data.CodexTurnStateLength)
}

func TestAdminUsageCodexTurnStateDetailRejectsMissingState(t *testing.T) {
	router := newCodexTurnStateHandlerRouter(&codexTurnStateUsageRepoStub{
		record: &service.UsageLog{ID: 7},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/7/codex-turn-state", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestAdminUsageCodexTurnStateDetailMapsMissingRecord(t *testing.T) {
	router := newCodexTurnStateHandlerRouter(&codexTurnStateUsageRepoStub{err: service.ErrUsageLogNotFound})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/999/codex-turn-state", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestAdminUsageCodexTurnStateDetailRejectsInvalidID(t *testing.T) {
	repo := &codexTurnStateUsageRepoStub{}
	router := newCodexTurnStateHandlerRouter(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/not-an-id/codex-turn-state", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestAdminUsageListContainsOnlyCodexTurnStateLength(t *testing.T) {
	state := "turn-state-secret"
	repo := &codexTurnStateUsageRepoStub{}
	listRepo := &codexTurnStateUsageListRepoStub{
		UsageLogRepository: repo,
		records:            []service.UsageLog{{ID: 7, CodexTurnState: &state}},
	}
	router := newCodexTurnStateHandlerRouter(listRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), state)
	require.Contains(t, rec.Body.String(), `"codex_turn_state_length":`)
}

type codexTurnStateUsageListRepoStub struct {
	service.UsageLogRepository
	records []service.UsageLog
}

func (s *codexTurnStateUsageListRepoStub) ListWithFilters(context.Context, pagination.PaginationParams, usagestats.UsageLogFilters) ([]service.UsageLog, *pagination.PaginationResult, error) {
	return s.records, &pagination.PaginationResult{Total: int64(len(s.records)), Page: 1, PageSize: 20, Pages: 1}, nil
}
