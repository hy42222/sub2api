package repository

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newCodexFingerprintPoolTestCache(t *testing.T) (*gatewayCache, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &gatewayCache{rdb: client}, server
}

func codexFingerprintRequest(accountID int64, source string, now time.Time) service.CodexFingerprintPoolResolveRequest {
	return service.CodexFingerprintPoolResolveRequest{
		AccountID:     accountID,
		SourceHash:    source,
		PoolSize:      2,
		IdleTimeout:   30 * 24 * time.Hour,
		Now:           now,
		WorkspaceJSON: fmt.Sprintf(`{"workspace":%q}`, source),
	}
}

func TestCodexFingerprintPoolStableBoundedAndRotatesOnlyIdle(t *testing.T) {
	cache, redisServer := newCodexFingerprintPoolTestCache(t)
	ctx := context.Background()
	t0 := time.Unix(1_800_000_000, 0)

	a, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-a", t0))
	require.NoError(t, err)
	aAgain, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-a", t0.Add(time.Hour)))
	require.NoError(t, err)
	require.Equal(t, a.InstallationID, aAgain.InstallationID)
	require.Equal(t, a.WorkspaceJSON, aAgain.WorkspaceJSON)

	b, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-b", t0.Add(2*time.Hour)))
	require.NoError(t, err)
	require.NotEqual(t, a.InstallationID, b.InstallationID)

	// A full, hot pool aliases new sources without replacing either persona.
	cHot, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-c", t0.Add(3*time.Hour)))
	require.NoError(t, err)
	require.Contains(t, []string{a.InstallationID, b.InstallationID}, cHot.InstallationID)
	cStable, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-c", t0.Add(4*time.Hour)))
	require.NoError(t, err)
	require.Equal(t, cHot.InstallationID, cStable.InstallationID)

	// Refresh B late enough that only A is idle when D arrives.
	bFresh, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-b", t0.Add(29*24*time.Hour)))
	require.NoError(t, err)
	require.Equal(t, b.InstallationID, bFresh.InstallationID)

	d, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-d", t0.Add(31*24*time.Hour)))
	require.NoError(t, err)
	require.NotEqual(t, a.InstallationID, d.InstallationID)
	require.NotEqual(t, b.InstallationID, d.InstallationID)
	require.Equal(t, a.Slot, d.Slot)
	require.Equal(t, a.Generation+1, d.Generation)

	// The old source owns the slot, not the retired generation. It must resolve
	// to the new UUID and can never resurrect A's old outbound identity.
	aAfterRotation, err := cache.ResolveCodexFingerprintPersona(ctx, codexFingerprintRequest(42, "source-a", t0.Add(32*24*time.Hour)))
	require.NoError(t, err)
	require.Equal(t, d.InstallationID, aAfterRotation.InstallationID)
	require.NotEqual(t, a.InstallationID, aAfterRotation.InstallationID)
	retired, err := redisServer.SIsMember(codexFingerprintPoolKeys(42)[3], a.InstallationID)
	require.NoError(t, err)
	require.True(t, retired)
}

func TestCodexFingerprintPoolConcurrentAllocationNeverExceedsCapacity(t *testing.T) {
	cache, redisServer := newCodexFingerprintPoolTestCache(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)

	const requests = 64
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			request := codexFingerprintRequest(77, fmt.Sprintf("source-%d", index), now)
			request.PoolSize = 3
			_, err := cache.ResolveCodexFingerprintPersona(ctx, request)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	lastSeen, err := redisServer.ZMembers(codexFingerprintPoolKeys(77)[1])
	require.NoError(t, err)
	require.Len(t, lastSeen, 3)
	ids, err := redisServer.HKeys(codexFingerprintPoolKeys(77)[0])
	require.NoError(t, err)
	var installationFields int
	for _, field := range ids {
		if len(field) >= 3 && field[:3] == "id:" {
			installationFields++
		}
	}
	require.Equal(t, 3, installationFields)
}
