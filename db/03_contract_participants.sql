-- Migration 03: Receiver-authority contract model
-- Replaces bilateral sender/receiver_partner_id with contract_participants table.
-- Idempotent — safe to re-run on databases where a previous attempt partially applied.

-- 1. Add receiver_node_id as varchar, or fix it if it was previously created as uuid
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'data_contracts' AND column_name = 'receiver_node_id'
    ) THEN
        ALTER TABLE data_contracts ADD COLUMN receiver_node_id varchar;
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'data_contracts'
          AND column_name = 'receiver_node_id'
          AND data_type = 'uuid'
    ) THEN
        ALTER TABLE data_contracts ALTER COLUMN receiver_node_id TYPE varchar;
    END IF;
END$$;

UPDATE data_contracts
SET receiver_node_id = (SELECT node_id FROM node_config LIMIT 1)
WHERE receiver_node_id IS NULL;

ALTER TABLE data_contracts ALTER COLUMN receiver_node_id SET NOT NULL;

-- 2. Participants table
CREATE TABLE IF NOT EXISTS contract_participants (
    contract_id  uuid        NOT NULL REFERENCES data_contracts(contract_id) ON DELETE CASCADE,
    node_id      varchar     NOT NULL,
    status       varchar     NOT NULL DEFAULT 'Invited'
                             CHECK (status IN ('Invited', 'Active', 'Rejected')),
    invited_at   timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contract_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_contract_participants_node
    ON contract_participants(node_id, status);

-- 3. Migrate existing bilateral contracts (only if sender_partner_id column still exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'data_contracts' AND column_name = 'sender_partner_id'
    ) THEN
        INSERT INTO contract_participants (contract_id, node_id, status, invited_at)
        SELECT contract_id, sender_partner_id, 'Active', updated_at
        FROM   data_contracts
        WHERE  sender_partner_id IS NOT NULL
        ON CONFLICT (contract_id, node_id) DO NOTHING;
    END IF;
END$$;

-- 4. Promote all existing contracts to Active (they were already agreed)
UPDATE data_contracts SET status = 'Active' WHERE status = 'Proposed';

-- 5. Drop legacy columns (each guarded by IF EXISTS)
ALTER TABLE data_contracts
    DROP COLUMN IF EXISTS sender_partner_id,
    DROP COLUMN IF EXISTS receiver_partner_id,
    DROP COLUMN IF EXISTS direction;
