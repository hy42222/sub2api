package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	adminhandler "github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestKeyIPAuditRoutesUseAdminAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handlers := &handler.Handlers{Admin: &handler.AdminHandlers{
		KeyIPAudit: adminhandler.NewKeyIPAuditHandler(nil, nil),
	}}
	auth := middleware.AdminAuthMiddleware(func(c *gin.Context) {
		switch c.GetHeader("Authorization") {
		case "admin":
			c.Next()
		case "user":
			c.AbortWithStatus(http.StatusForbidden)
		default:
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})
	RegisterAdminRoutes(router.Group("/api/v1"), handlers, auth,
		middleware.AuditLogMiddleware(func(c *gin.Context) { c.Next() }),
		middleware.StepUpAuthMiddleware(func(c *gin.Context) { c.Next() }), nil, nil)

	for _, endpoint := range []struct{ method, path string }{
		{"GET", "/keys?page=invalid"},
		{"GET", "/keys/invalid"},
		{"POST", "/keys/invalid/disable"},
		{"POST", "/keys/invalid/rotate"},
		{"GET", "/trusted?page=invalid"},
		{"POST", "/trusted"},
		{"DELETE", "/trusted/invalid"},
		{"POST", "/dismissals"},
		{"DELETE", "/dismissals/invalid"},
	} {
		for _, role := range []struct {
			name string
			want int
		}{{"", http.StatusUnauthorized}, {"user", http.StatusForbidden}, {"admin", http.StatusBadRequest}} {
			t.Run(endpoint.method+endpoint.path+"/"+role.name, func(t *testing.T) {
				req := httptest.NewRequest(endpoint.method, "/api/v1/admin/key-ip-audit"+endpoint.path, nil)
				req.Header.Set("Authorization", role.name)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				require.Equal(t, role.want, w.Code, w.Body.String())
			})
		}
	}
}
