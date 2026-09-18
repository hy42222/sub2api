-- Store the final X-Codex-Turn-State request value sent to an upstream Codex account.
-- Historical and non-Codex usage rows remain NULL.
ALTER TABLE usage_logs
    ADD COLUMN IF NOT EXISTS codex_turn_state TEXT;
