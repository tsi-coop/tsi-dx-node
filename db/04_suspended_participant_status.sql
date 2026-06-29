-- Migration 04: Add 'Suspended' as a valid participant status
-- Required for receiver-initiated deactivation of individual senders.

ALTER TABLE contract_participants
    DROP CONSTRAINT IF EXISTS contract_participants_status_check;

ALTER TABLE contract_participants
    ADD CONSTRAINT contract_participants_status_check
    CHECK (status IN ('Invited', 'Active', 'Rejected', 'Suspended'));
