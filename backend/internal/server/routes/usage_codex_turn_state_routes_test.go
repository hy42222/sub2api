package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	adminhandler "github.com/Wei-Shaw/sub2api/internal/handler/admin"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type adminUsageRouteRepoStub struct {
	service.UsageLogRepository
	record *service.UsageLog
}

func (s *adminUsageRouteRepoStub) GetByID(context.Context, int64) (*service.UsageLog, error) {
	return s.record, nil
}

func TestAdminUsageCodexTurnStateRouteUsesAdminAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	state := "route-state-secret"
	usageService := service.NewUsageService(&adminUsageRouteRepoStub{
		record: &service.UsageLog{ID: 7, CodexTurnState: &state},
	}, nil, nil, nil)
	handlers := &handler.Handlers{Admin: &handler.AdminHandlers{
		Usage: adminhandler.NewUsageHandler(usageService, nil, nil, nil),
	}}
	auth := servermiddleware.AdminAuthMiddleware(func(c *gin.Context) {
		switch c.GetHeader("Authorization") {
		case "admin":
			c.Next()
		case "user":
			c.AbortWithStatus(http.StatusForbidden)
		default:
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	admin := router.Group("/api/v1/admin")
	admin.Use(gin.HandlerFunc(auth))
	registerUsageRoutes(admin, handlers)

	for _, tc := range []struct {
		name       string
		auth       string
		wantStatus int
	}{
		{name: "unauthenticated", wantStatus: http.StatusUnauthorized},
		{name: "non-admin", auth: "user", wantStatus: http.StatusForbidden},
		{name: "admin", auth: "admin", wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/usage/7/codex-turn-state", nil)
			req.Header.Set("Authorization", tc.auth)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, tc.wantStatus, rec.Code)
			if tc.name == "admin" {
				require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
				require.Contains(t, rec.Body.String(), state)
			}
		})
	}
}
