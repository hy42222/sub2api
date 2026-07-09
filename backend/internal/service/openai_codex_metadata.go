package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// saltCodexTurnMetadata applies account-salted HMAC rewriting to
// x-codex-turn-metadata JSON to prevent cross-account user fingerprinting.
func saltCodexTurnMetadata(raw string, account *Account, isolatedSessionID string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || account == nil {
		return raw
	}

	var meta map[string]any
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return raw
	}

	accountSecret := fmt.Sprintf("acct_%d_xcodex_metadata", account.ID)
	if isolatedSessionID != "" {
		meta["session_id"] = isolatedSessionID
	}
	meta["installation_id"] = hmacHex("installation", accountSecret)
	meta["window_id"] = hmacHex("window", accountSecret)

	fingerprint := extractWorkspaceFingerprint(meta)
	if fingerprint != "" {
		originalWS := extractWorkspacesJSON(meta)
		pool := getOrCreateWorkspacePool(account)
		if replacement := pool.resolve(fingerprint, originalWS); replacement != originalWS {
			var ws map[string]any
			if json.Unmarshal([]byte(replacement), &ws) == nil {
				meta["workspaces"] = ws
			}
		}
	} else {
		delete(meta, "workspaces")
	}

	meta["turn_started_at_unix_ms"] = time.Now().UnixMilli() + int64(account.ID%41-20)

	result, err := json.Marshal(meta)
	if err != nil {
		return raw
	}
	return string(result)
}

func hmacHex(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
