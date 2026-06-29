-- ============================================================
-- TSI DX Node - Sync Data Contracts Schema Migration
-- Additive only: no existing tables or columns are modified.
-- Run after init.sql.
-- ============================================================

-- 1. Extend data_contracts with interaction style
--    Existing rows default to 'async' - no backfill required.
ALTER TABLE data_contracts
    ADD COLUMN IF NOT EXISTS interaction_type VARCHAR(50) NOT NULL DEFAULT 'async';

-- sync_responder_url and sync_timeout_ms are stored in the
-- existing metadata JSONB column - no additional columns needed.

-- 2. Nonce registry for sync replay protection
--    TTL-based: the receiver inserts a nonce on first sight;
--    a second request carrying the same nonce is rejected.
--    Expired rows can be purged by a maintenance job.
CREATE TABLE IF NOT EXISTS sync_nonces (
    nonce_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id     UUID REFERENCES data_contracts(contract_id) ON DELETE CASCADE,
    nonce           VARCHAR(255) NOT NULL UNIQUE,
    idempotency_key VARCHAR(255),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sync_nonces_nonce   ON sync_nonces(nonce);
CREATE INDEX IF NOT EXISTS idx_sync_nonces_expires ON sync_nonces(expires_at);

-- 3. Immutable per-call audit log for synchronous exchanges
--    Parallel to data_transfers for the async lane.
--    Both caller and receiver write one row per call.
CREATE TABLE IF NOT EXISTS sync_audit_log (
    log_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id      UUID REFERENCES data_contracts(contract_id) ON DELETE SET NULL,
    idempotency_key  VARCHAR(255),
    request_payload  JSONB,
    response_payload JSONB,
    sender_node_id   VARCHAR(255),
    receiver_node_id VARCHAR(255),
    duration_ms      BIGINT,
    status           VARCHAR(50) NOT NULL,  -- SUCCESS, TIMEOUT, ERROR
    error_detail     TEXT,
    timestamp        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sync_audit_log_contract   ON sync_audit_log(contract_id);
CREATE INDEX IF NOT EXISTS idx_sync_audit_log_timestamp  ON sync_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_sync_audit_log_status     ON sync_audit_log(status);
