package repository

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const codexFingerprintPoolPrefix = "codex_fp:"

var codexFingerprintPoolResolveScript = redis.NewScript(`
local slots_key = KEYS[1]
local last_seen_key = KEYS[2]
local source_map_key = KEYS[3]
local retired_key = KEYS[4]

local source_hash = ARGV[1]
local pool_size = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local idle_ms = tonumber(ARGV[4])
local candidate_id = ARGV[5]
local candidate_workspace = ARGV[6]
local alias_rank = tonumber(ARGV[7])

local function result_for(slot, action)
  local installation_id = redis.call('HGET', slots_key, 'id:' .. slot)
  local workspace = redis.call('HGET', slots_key, 'ws:' .. slot) or ''
  local generation = redis.call('HGET', slots_key, 'gen:' .. slot) or '1'
  return {installation_id, workspace, tostring(slot), generation, action}
end

local mapped_slot = redis.call('HGET', source_map_key, source_hash)
if mapped_slot then
  if redis.call('HEXISTS', slots_key, 'id:' .. mapped_slot) == 1 then
    redis.call('ZADD', last_seen_key, now_ms, mapped_slot)
    return result_for(mapped_slot, 'reuse')
  end
  redis.call('HDEL', source_map_key, source_hash)
end

local active_count = redis.call('ZCARD', last_seen_key)
local shrunk = false
-- A reduced configuration never evicts a hot persona. On a new source, trim
-- only generations that already satisfy the same idle rule used for rotation.
while active_count > pool_size do
  local shrink_oldest = redis.call('ZRANGE', last_seen_key, 0, 0, 'WITHSCORES')
  if #shrink_oldest ~= 2 or now_ms - tonumber(shrink_oldest[2]) < idle_ms then
    break
  end
  local shrink_slot = shrink_oldest[1]
  local shrink_id = redis.call('HGET', slots_key, 'id:' .. shrink_slot)
  if shrink_id then
    redis.call('SADD', retired_key, shrink_id)
  end
  redis.call('HDEL', slots_key, 'id:' .. shrink_slot, 'ws:' .. shrink_slot, 'gen:' .. shrink_slot)
  redis.call('ZREM', last_seen_key, shrink_slot)
  active_count = active_count - 1
  shrunk = true
end
if active_count < pool_size then
  if redis.call('SISMEMBER', retired_key, candidate_id) == 1 then
    return {'', '', '', '', 'candidate_retired'}
  end
  local slot = 0
  while slot < pool_size and redis.call('HEXISTS', slots_key, 'id:' .. slot) == 1 do
    slot = slot + 1
  end
  if slot >= pool_size then
    return {'', '', '', '', 'inconsistent_pool'}
  end
  redis.call('HSET', slots_key,
    'id:' .. slot, candidate_id,
    'ws:' .. slot, candidate_workspace,
    'gen:' .. slot, 1)
  redis.call('ZADD', last_seen_key, now_ms, slot)
  redis.call('HSET', source_map_key, source_hash, slot)
  return result_for(slot, 'allocate')
end

local oldest = redis.call('ZRANGE', last_seen_key, 0, 0, 'WITHSCORES')
if not shrunk and #oldest == 2 and now_ms - tonumber(oldest[2]) >= idle_ms then
  if redis.call('SISMEMBER', retired_key, candidate_id) == 1 then
    return {'', '', '', '', 'candidate_retired'}
  end
  local slot = oldest[1]
  local old_id = redis.call('HGET', slots_key, 'id:' .. slot)
  if old_id then
    redis.call('SADD', retired_key, old_id)
  end
  local generation = tonumber(redis.call('HGET', slots_key, 'gen:' .. slot) or '1') + 1
  redis.call('HSET', slots_key,
    'id:' .. slot, candidate_id,
    'ws:' .. slot, candidate_workspace,
    'gen:' .. slot, generation)
  redis.call('ZADD', last_seen_key, now_ms, slot)
  redis.call('HSET', source_map_key, source_hash, slot)
  return result_for(slot, 'rotate')
end

if active_count == 0 then
  return {'', '', '', '', 'inconsistent_pool'}
end
local rank = alias_rank % active_count
local selected = redis.call('ZRANGE', last_seen_key, rank, rank)
if #selected ~= 1 then
  return {'', '', '', '', 'inconsistent_pool'}
end
local slot = selected[1]
redis.call('ZADD', last_seen_key, now_ms, slot)
redis.call('HSET', source_map_key, source_hash, slot)
return result_for(slot, 'alias')
`)

func codexFingerprintPoolKeys(accountID int64) []string {
	tag := fmt.Sprintf("{%d}", accountID)
	base := codexFingerprintPoolPrefix + tag
	return []string{
		base + ":slots",
		base + ":last_seen",
		base + ":source_map",
		base + ":retired",
	}
}

func (c *gatewayCache) ResolveCodexFingerprintPersona(ctx context.Context, request service.CodexFingerprintPoolResolveRequest) (service.CodexFingerprintPersona, error) {
	if c == nil || c.rdb == nil {
		return service.CodexFingerprintPersona{}, errors.New("codex fingerprint pool cache is unavailable")
	}
	if request.AccountID <= 0 || request.PoolSize <= 0 || request.SourceHash == "" {
		return service.CodexFingerprintPersona{}, errors.New("invalid codex fingerprint pool request")
	}
	if request.Now.IsZero() {
		request.Now = time.Now()
	}
	if request.IdleTimeout <= 0 {
		return service.CodexFingerprintPersona{}, errors.New("invalid codex fingerprint idle timeout")
	}

	aliasRank := stableCodexFingerprintAliasRank(request.SourceHash)
	for attempts := 0; attempts < 4; attempts++ {
		candidateID := uuid.NewString()
		values, err := codexFingerprintPoolResolveScript.Run(
			ctx,
			c.rdb,
			codexFingerprintPoolKeys(request.AccountID),
			request.SourceHash,
			request.PoolSize,
			request.Now.UnixMilli(),
			request.IdleTimeout.Milliseconds(),
			candidateID,
			request.WorkspaceJSON,
			aliasRank,
		).Slice()
		if err != nil {
			return service.CodexFingerprintPersona{}, fmt.Errorf("resolve codex fingerprint persona: %w", err)
		}
		if len(values) != 5 {
			return service.CodexFingerprintPersona{}, fmt.Errorf("resolve codex fingerprint persona: unexpected result length %d", len(values))
		}
		action := redisString(values[4])
		if action == "candidate_retired" {
			continue
		}
		if action == "inconsistent_pool" {
			return service.CodexFingerprintPersona{}, errors.New("resolve codex fingerprint persona: inconsistent pool state")
		}
		slot, err := strconv.Atoi(redisString(values[2]))
		if err != nil {
			return service.CodexFingerprintPersona{}, fmt.Errorf("resolve codex fingerprint persona slot: %w", err)
		}
		generation, err := strconv.ParseInt(redisString(values[3]), 10, 64)
		if err != nil {
			return service.CodexFingerprintPersona{}, fmt.Errorf("resolve codex fingerprint persona generation: %w", err)
		}
		persona := service.CodexFingerprintPersona{
			InstallationID: redisString(values[0]),
			WorkspaceJSON:  redisString(values[1]),
			Slot:           slot,
			Generation:     generation,
		}
		if persona.InstallationID == "" {
			return service.CodexFingerprintPersona{}, errors.New("resolve codex fingerprint persona: empty installation id")
		}
		return persona, nil
	}
	return service.CodexFingerprintPersona{}, errors.New("resolve codex fingerprint persona: could not generate a non-retired id")
}

func stableCodexFingerprintAliasRank(sourceHash string) int64 {
	var rank uint64
	for i := 0; i < len(sourceHash) && i < 16; i++ {
		rank = rank*131 + uint64(sourceHash[i])
	}
	return int64(rank & 0x7fffffffffffffff)
}

func redisString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return fmt.Sprint(value)
	}
}

var _ service.CodexFingerprintPoolCache = (*gatewayCache)(nil)
