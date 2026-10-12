-- ============================================================
-- TSI DX Node - Transfer retry bookkeeping
-- Additive only. The node also applies these statements at start-up
-- (TransferEngine.ensureSchema), so existing databases need no manual step.
-- ============================================================
ALTER TABLE data_transfers ADD COLUMN IF NOT EXISTS retry_count    INT NOT NULL DEFAULT 0;
ALTER TABLE data_transfers ADD COLUMN IF NOT EXISTS next_retry_at  TIMESTAMP WITH TIME ZONE NULL;
