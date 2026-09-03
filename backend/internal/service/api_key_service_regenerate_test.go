//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type regenerateAPIKeyRepoStub struct {
	APIKeyRepository
	key          *APIKey
	updateErrs   []error
	updatedKeys  []APIKey
	updateFields []APIKeyUpdateFields
}

func (r *regenerateAPIKeyRepoStub) GetByID(context.Context, int64) (*APIKey, error) {
	clone := *r.key
	return &clone, nil
}

func (r *regenerateAPIKeyRepoStub) Update(_ context.Context, key *APIKey, fields APIKeyUpdateFields) error {
	r.updatedKeys = append(r.updatedKeys, *key)
	r.updateFields = append(r.updateFields, fields)
	if len(r.updateErrs) > 0 {
		err := r.updateErrs[0]
		r.updateErrs = r.updateErrs[1:]
		return err
	}
	r.key = key
	return nil
}

type regenerateAPIKeyCacheStub struct {
	APIKeyCache
	deletedKeys []string
}

func (c *regenerateAPIKeyCacheStub) DeleteAuthCache(_ context.Context, key string) error {
	c.deletedKeys = append(c.deletedKeys, key)
	return nil
}

func (c *regenerateAPIKeyCacheStub) PublishAuthCacheInvalidation(context.Context, string) error {
	return nil
}

func newRegenerateAPIKeyService(key *APIKey, updateErrs ...error) (*APIKeyService, *regenerateAPIKeyRepoStub, *regenerateAPIKeyCacheStub) {
	repo := &regenerateAPIKeyRepoStub{key: key, updateErrs: updateErrs}
	cache := &regenerateAPIKeyCacheStub{}
	svc := NewAPIKeyService(repo, nil, nil, nil, nil, cache, &config.Config{})
	return svc, repo, cache
}

func TestAPIKeyServiceRegenerateKeyPreservesRecordAndInvalidatesCaches(t *testing.T) {
	key := &APIKey{
		ID:          7,
		UserID:      42,
		Key:         "sk-old-credential",
		Name:        "production",
		Status:      StatusAPIKeyActive,
		Quota:       100,
		QuotaUsed:   23.5,
		RateLimit5h: 40,
		Usage5h:     12.5,
	}
	svc, repo, cache := newRegenerateAPIKeyService(key)

	regenerated, err := svc.RegenerateKey(context.Background(), key.ID, key.UserID)

	require.NoError(t, err)
	require.NotNil(t, regenerated)
	require.NotEqual(t, key.Key, regenerated.Key)
	require.Equal(t, key.Name, regenerated.Name)
	require.Equal(t, key.Status, regenerated.Status)
	require.Equal(t, key.Quota, regenerated.Quota)
	require.Equal(t, key.QuotaUsed, regenerated.QuotaUsed)
	require.Equal(t, key.RateLimit5h, regenerated.RateLimit5h)
	require.Equal(t, key.Usage5h, regenerated.Usage5h)
	require.Equal(t, []APIKeyUpdateFields{{Key: true}}, repo.updateFields)
	require.Equal(t, regenerated.Key, repo.key.Key)
	require.Equal(t, []string{svc.authCacheKey(key.Key), svc.authCacheKey(regenerated.Key)}, cache.deletedKeys)
}

func TestAPIKeyServiceRegenerateKeyRejectsNonOwner(t *testing.T) {
	key := &APIKey{ID: 7, UserID: 42, Key: "sk-old-credential"}
	svc, repo, cache := newRegenerateAPIKeyService(key)

	regenerated, err := svc.RegenerateKey(context.Background(), key.ID, 99)

	require.ErrorIs(t, err, ErrInsufficientPerms)
	require.Nil(t, regenerated)
	require.Empty(t, repo.updatedKeys)
	require.Empty(t, cache.deletedKeys)
}

func TestAPIKeyServiceRegenerateKeyRetriesUniqueConflict(t *testing.T) {
	key := &APIKey{ID: 7, UserID: 42, Key: "sk-old-credential"}
	svc, repo, cache := newRegenerateAPIKeyService(key, ErrAPIKeyExists)

	regenerated, err := svc.RegenerateKey(context.Background(), key.ID, 42)

	require.NoError(t, err)
	require.NotNil(t, regenerated)
	require.Len(t, repo.updatedKeys, 2)
	require.NotEqual(t, repo.updatedKeys[0].Key, repo.updatedKeys[1].Key)
	require.Equal(t, []APIKeyUpdateFields{{Key: true}, {Key: true}}, repo.updateFields)
	require.Len(t, cache.deletedKeys, 2)
}
