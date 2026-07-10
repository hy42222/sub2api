package service

import (
	"encoding/json"
	"sync"
	"time"
)

// WorkspaceFingerprintIdleTimeout is the idle duration after which a workspace
// profile is evicted from the fingerprint pool. Defaults to 15 minutes.
// Profiles that are actively used (lastUsedAt refreshed by matching requests)
// are never evicted regardless of this timeout.
var WorkspaceFingerprintIdleTimeout = 15 * time.Minute

// workspaceProfileSnapshot holds a real user's workspace data, preserved as-is
// for reuse as a fingerprint profile.
type workspaceProfileSnapshot struct {
	jsonData    string    // original serialized workspaces JSON
	fingerprint string    // origin remote URL (or fallback)
	lastUsedAt  time.Time // for LRU ordering and idle eviction
}

// accountWorkspacePool maintains a bounded set of real workspace profiles
// for a single upstream account. Pool size is capped at the account's
// concurrency limit so the number of distinct workspace fingerprints never
// exceeds the number of concurrent upstream sessions.
type accountWorkspacePool struct {
	mu      sync.Mutex
	entries []*workspaceProfileSnapshot // ordered by lastUsedAt: [0]=LRU, [len-1]=MRU
	maxSize int
}

var workspaceFingerprintPools sync.Map // map[int64]*accountWorkspacePool

// getOrCreateWorkspacePool returns the per-account pool, creating one if needed.
func getOrCreateWorkspacePool(account *Account) *accountWorkspacePool {
	if account == nil {
		return nil
	}
	if v, ok := workspaceFingerprintPools.Load(account.ID); ok {
		return v.(*accountWorkspacePool)
	}
	maxSize := account.Concurrency
	if maxSize <= 0 {
		maxSize = 1
	}
	pool := &accountWorkspacePool{
		entries: make([]*workspaceProfileSnapshot, 0, maxSize),
		maxSize: maxSize,
	}
	actual, _ := workspaceFingerprintPools.LoadOrStore(account.ID, pool)
	return actual.(*accountWorkspacePool)
}

// resolve resolves a workspace fingerprint against the pool.
// Returns the workspaces JSON to use for this request.
// When the fingerprint is already in the pool or the pool has room,
// the original workspaces are kept. When the pool is full and all
// entries are recently active, the MRU entry's workspaces
// are returned as a replacement.
func (p *accountWorkspacePool) resolve(fingerprint string, originalWorkspacesJSON string) string {
	if p == nil || fingerprint == "" {
		return originalWorkspacesJSON
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-WorkspaceFingerprintIdleTimeout)

	// 1. Evict idle entries (past idle timeout, based on lastUsedAt).
	fresh := make([]*workspaceProfileSnapshot, 0, len(p.entries))
	for _, e := range p.entries {
		if e.lastUsedAt.After(cutoff) {
			fresh = append(fresh, e)
		}
	}
	p.entries = fresh

	// 2. Check if fingerprint already in pool → refresh LRU, keep.
	for i, e := range p.entries {
		if e.fingerprint == fingerprint {
			e.lastUsedAt = now
			// Move to MRU end.
			p.entries = append(append(p.entries[:i], p.entries[i+1:]...), e)
			return originalWorkspacesJSON
		}
	}

	// 3. Pool has room → admit new fingerprint, keep.
	if len(p.entries) < p.maxSize {
		entry := &workspaceProfileSnapshot{
			jsonData:    originalWorkspacesJSON,
			fingerprint: fingerprint,
			lastUsedAt:  now,
		}
		p.entries = append(p.entries, entry)
		return originalWorkspacesJSON
	}

	// 4. Pool full + all entries active → replace with MRU entry's workspaces.
	// MRU is the last entry (index len-1 after sorting).
	mru := p.entries[len(p.entries)-1]
	mru.lastUsedAt = now
	return mru.jsonData
}

// extractWorkspaceFingerprint extracts a stable fingerprint key from
// x-codex-turn-metadata JSON. Prefers origin remote URL; falls back
// to any available remote URL → commit hash → empty string.
func extractWorkspaceFingerprint(meta map[string]any) string {
	workspaces, ok := meta["workspaces"].(map[string]any)
	if !ok || len(workspaces) == 0 {
		return ""
	}
	for _, v := range workspaces {
		ws, ok := v.(map[string]any)
		if !ok {
			continue
		}
		remotes, ok := ws["associated_remote_urls"].(map[string]any)
		if ok {
			// Prefer "origin".
			if origin, ok := remotes["origin"].(string); ok && origin != "" {
				return "origin:" + origin
			}
			// Fallback: first remote.
			for name, url := range remotes {
				if s, ok := url.(string); ok && s != "" {
					return name + ":" + s
				}
			}
		}
		// Fallback: commit hash.
		if hash, ok := ws["latest_git_commit_hash"].(string); ok && hash != "" {
			return "commit:" + hash
		}
	}
	return ""
}

// extractWorkspacesJSON extracts and serializes just the "workspaces" field
// from a parsed x-codex-turn-metadata map.
func extractWorkspacesJSON(meta map[string]any) string {
	ws, ok := meta["workspaces"]
	if !ok || ws == nil {
		return ""
	}
	raw, err := json.Marshal(ws)
	if err != nil {
		return ""
	}
	return string(raw)
}
