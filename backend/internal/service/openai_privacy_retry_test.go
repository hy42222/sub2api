//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
)

type privacyProxyListerStub struct {
	proxies []Proxy
	err     error
}

func (s privacyProxyListerStub) ListActive(context.Context) ([]Proxy, error) {
	return s.proxies, s.err
}

func TestRunOpenAIPrivacyWithProxyFallback(t *testing.T) {
	t.Parallel()

	expiredAt := time.Now().Add(-time.Minute)
	proxies := []Proxy{
		{ID: 3, Protocol: "http", Host: "success.example", Port: 8080, Status: StatusActive},
		{ID: 1, Protocol: "http", Host: "expired.example", Port: 8080, Status: StatusActive, ExpiresAt: &expiredAt},
		{ID: 2, Protocol: "http", Host: "retry.example", Port: 8080, Status: StatusActive},
	}
	preferred := "http://preferred.example:8080"
	var attempts []string

	mode := runOpenAIPrivacyWithProxyFallback(
		context.Background(),
		preferred,
		privacyProxyListerStub{proxies: proxies},
		func(proxyURL string) string {
			attempts = append(attempts, proxyURL)
			if proxyURL == "http://success.example:8080" {
				return PrivacyModeTrainingOff
			}
			return PrivacyModeFailed
		},
	)

	require.Equal(t, PrivacyModeTrainingOff, mode)
	require.Equal(t, []string{
		preferred,
		"http://retry.example:8080",
		"http://success.example:8080",
	}, attempts)
}

func TestAdminService_EnsureOpenAIPrivacy_RetriesNonSuccessModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{PrivacyModeFailed, PrivacyModeCFBlocked} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			privacyCalls := 0
			svc := &adminServiceImpl{
				accountRepo: &mockAccountRepoForGemini{},
				privacyClientFactory: func(proxyURL string) (*req.Client, error) {
					privacyCalls++
					return nil, errors.New("factory failed")
				},
			}

			account := &Account{
				ID:       101,
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Credentials: map[string]any{
					"access_token": "token-1",
				},
				Extra: map[string]any{
					"privacy_mode": mode,
				},
			}

			got := svc.EnsureOpenAIPrivacy(context.Background(), account)

			require.Equal(t, PrivacyModeFailed, got)
			require.Equal(t, 1, privacyCalls)
		})
	}
}

func TestTokenRefreshService_ensureOpenAIPrivacy_RetriesNonSuccessModes(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}

	for _, mode := range []string{PrivacyModeFailed, PrivacyModeCFBlocked} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			service := NewTokenRefreshService(&tokenRefreshAccountRepo{}, nil, nil, nil, nil, nil, nil, cfg, nil)
			privacyCalls := 0
			service.SetPrivacyDeps(func(proxyURL string) (*req.Client, error) {
				privacyCalls++
				return nil, errors.New("factory failed")
			}, nil)

			account := &Account{
				ID:       202,
				Platform: PlatformOpenAI,
				Type:     AccountTypeOAuth,
				Credentials: map[string]any{
					"access_token": "token-2",
				},
				Extra: map[string]any{
					"privacy_mode": mode,
				},
			}

			service.ensureOpenAIPrivacy(context.Background(), account)

			require.Equal(t, 1, privacyCalls)
		})
	}
}
