-- init.sql
-- Database initialization script for TSI DX Node PostgreSQL database.
-- This script will be executed automatically by the PostgreSQL Docker image
-- when the container starts for the first time.

-- Ensure UUID generation function is available (for PostgreSQL 12 and older, if not already enabled)
-- For PostgreSQL 13+, gen_random_uuid() is built-in and doesn't require this extension.
-- It's safe to run this command as it will only create the extension if it doesn't exist.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Set timezone for consistency
SET TIMEZONE TO 'UTC';

-- 1. `partners` Table
-- Stores information about registered DX Node partners.
CREATE TABLE partners (
    partner_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    fqdn VARCHAR(255) NOT NULL UNIQUE,
    public_key_pem TEXT NOT NULL,
    public_key_fingerprint VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) NOT NULL DEFAULT 'Pending', -- 'Pending', 'Active', 'Inactive'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for partners table
CREATE INDEX idx_partners_node_id ON partners (node_id);
CREATE INDEX idx_partners_fqdn ON partners (fqdn);

-- 3. `roles` Table
-- Defines different roles within the Admin App.
CREATE TABLE roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NULL,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 2. `users` Table (MODIFIED)
-- Stores information about local users who can access the Admin App.
-- Now includes a direct role_id foreign key, ensuring each user has exactly one role.
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT, -- Foreign key to the roles table
    status VARCHAR(50) NOT NULL DEFAULT 'Active', -- 'Active', 'Inactive', 'Locked'
    last_login_at TIMESTAMP WITH TIME ZONE NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for users table
CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_role_id ON users (role_id); -- New index for the role_id

-- 4. `user_roles` Table (REMOVED - This table is no longer needed)

-- 5. `role_permissions` Table
-- Stores granular permissions for each role.
CREATE TABLE role_permissions (
    permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    UNIQUE (role_id, resource, action)
);

-- 6. `api_keys` Table
-- Stores API keys and secrets for Client API access.
CREATE TABLE api_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key VARCHAR(255) NOT NULL UNIQUE,
    api_secret_hash VARCHAR(255) NOT NULL,
    user_id UUID NULL REFERENCES users(user_id) ON DELETE SET NULL, -- User who generated/owns this key
    description TEXT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Active', -- 'Active', 'Inactive', 'Revoked'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NULL,
    last_used_at TIMESTAMP WITH TIME ZONE NULL
);

-- 7. `validation_scripts` Table
-- Stores custom data validation scripts.
CREATE TABLE validation_scripts (
    script_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    language VARCHAR(50) NOT NULL, -- 'PYTHON', 'JAVASCRIPT'
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 8. `data_contracts` Table
-- Defines the agreements for data exchange between partners.
CREATE TABLE data_contracts (
    contract_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    description TEXT NULL,
    sender_partner_id UUID NOT NULL REFERENCES partners(partner_id) ON DELETE RESTRICT,
    receiver_partner_id UUID NOT NULL REFERENCES partners(partner_id) ON DELETE RESTRICT,
    schema_definition JSONB NOT NULL,
    metadata JSONB NULL, -- Additional contract metadata (purpose, security classification)
    validation_script_id UUID NULL REFERENCES validation_scripts(script_id) ON DELETE SET NULL,
    retention_policy_days INT NULL, -- Data retention period in days for this contract
    pii_fields TEXT[] NULL, -- Array of field names identified as PII
    status VARCHAR(50) NOT NULL DEFAULT 'Draft', -- 'Draft', 'Proposed', 'Active', 'Terminated', 'Rejected'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for data_contracts table
CREATE INDEX idx_data_contracts_sender_partner_id ON data_contracts (sender_partner_id);
CREATE INDEX idx_data_contracts_receiver_partner_id ON data_contracts (receiver_partner_id);

-- 9. `bulk_uploads` Table
-- Tracks the overall status and details of bulk data upload operations.
CREATE TABLE bulk_uploads (
    bulk_upload_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    initiated_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    target_partner_ids UUID[] NOT NULL, -- Array of partner IDs targeted by this bulk upload.
    contract_id UUID NOT NULL REFERENCES data_contracts(contract_id) ON DELETE RESTRICT,
    total_files INT NOT NULL,
    successful_files INT NOT NULL DEFAULT 0,
    failed_files INT NOT NULL DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'Initiated', -- 'Initiated', 'Processing', 'Completed', 'Failed'
    start_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    end_time TIMESTAMP WITH TIME ZONE NULL,
    error_summary TEXT NULL
);

-- 10. `data_transfers` Table
-- Records details of each data transfer event.
CREATE TABLE data_transfers (
    transfer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bulk_upload_id UUID NULL REFERENCES bulk_uploads(bulk_upload_id) ON DELETE SET NULL, -- Optional: Foreign key to bulk upload
    contract_id UUID NOT NULL REFERENCES data_contracts(contract_id) ON DELETE RESTRICT,
    sender_node_id VARCHAR(255) NOT NULL,
    receiver_node_id VARCHAR(255) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    file_checksum VARCHAR(255) NOT NULL,
    sequence_number BIGINT NOT NULL,
    message_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Pending', -- 'Pending', 'Processing', 'Sent', 'Received', 'Failed', 'Delivered'
    error_message TEXT NULL,
    local_file_path TEXT NULL, -- Local path to the stored data file (for received/archived)
    initiated_by_user_id UUID NULL REFERENCES users(user_id) ON DELETE SET NULL, -- Optional: User who initiated the transfer
    start_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    end_time TIMESTAMP WITH TIME ZONE NULL
);

-- Indexes for data_transfers table
CREATE INDEX idx_data_transfers_contract_id ON data_transfers (contract_id);
CREATE INDEX idx_data_transfers_sender_node_id ON data_transfers (sender_node_id);
CREATE INDEX idx_data_transfers_receiver_node_id ON data_transfers (receiver_node_id);
CREATE INDEX idx_data_transfers_status ON data_transfers (status);
CREATE INDEX idx_data_transfers_bulk_upload_id ON data_transfers (bulk_upload_id);


-- 11. `audit_logs` Table
-- Records all significant events within the DX Node for auditing purposes.
CREATE TABLE audit_logs (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'INFO', -- 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    actor_type VARCHAR(50) NOT NULL, -- 'User', 'System', 'PartnerNode'
    actor_id VARCHAR(255) NOT NULL, -- ID of the actor (user_id, node_id, or 'system')
    entity_type VARCHAR(100) NULL, -- Type of entity affected (e.g., 'Partner', 'Contract', 'Transfer', 'User')
    entity_id UUID NULL, -- ID of the affected entity
    details JSONB NULL, -- JSON object with additional event details
    origin_ip INET NULL -- IP address from which the action originated
);

-- Indexes for audit_logs table
CREATE INDEX idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_actor_id ON audit_logs (actor_id);

-- 12. `received_sequence_tracker` Table
-- Tracks the last successfully processed sequence number from each sender for replay protection.
CREATE TABLE received_sequence_tracker (
    tracker_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_node_id VARCHAR(255) NOT NULL,
    receiver_node_id VARCHAR(255) NOT NULL,
    contract_id UUID NOT NULL REFERENCES data_contracts(contract_id) ON DELETE RESTRICT,
    last_received_sequence_number BIGINT NOT NULL DEFAULT 0,
    last_received_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '1970-01-01 00:00:00Z',
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (sender_node_id, receiver_node_id, contract_id)
);

-- Index for received_sequence_tracker table
CREATE INDEX idx_received_sequence_tracker_sender_node_id ON received_sequence_tracker (sender_node_id);

-- 13. `pii_rules` Table
-- Stores rules for Personally Identifiable Information (PII) anonymization.
CREATE TABLE pii_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    field_name VARCHAR(255) NOT NULL,
    anonymization_method VARCHAR(50) NOT NULL, -- 'HASH', 'MASK', 'TOKENIZE', 'REDACT'
    config JSONB NULL, -- JSON object for method-specific configurations
    description TEXT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 14. `node_config` Table (Added for NodeManagement class)
-- Stores the single configuration entry for the local DX Node.
CREATE TABLE node_config (
    config_id UUID PRIMARY KEY DEFAULT '00000000-0000-0000-0000-000000000001', -- Singleton ID
    node_id VARCHAR(255) NOT NULL UNIQUE,
    fqdn VARCHAR(255) NOT NULL UNIQUE,
    network_port INT NOT NULL,
    storage_active_path TEXT NOT NULL,
    storage_archive_path TEXT NOT NULL,
    logging_level VARCHAR(50) NOT NULL DEFAULT 'INFO', -- e.g., INFO, DEBUG, ERROR
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 15. `node_certificates` Table (Added for NodeManagement class to store PKI assets)
-- Stores certificates and private keys associated with the local DX Node.
CREATE TABLE node_certificates (
    cert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_config_id UUID NOT NULL REFERENCES node_config(config_id) ON DELETE CASCADE,
    certificate_pem TEXT NULL, -- Can be null if only private key is stored initially (e.g., after CSR generation)
    private_key_pem TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    issued_at TIMESTAMP WITH TIME ZONE NULL,
    expires_at TIMESTAMP WITH TIME ZONE NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add triggers to automatically update `updated_at` columns
-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers to relevant tables
CREATE TRIGGER update_partners_updated_at
BEFORE UPDATE ON partners
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at
BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at
BEFORE UPDATE ON api_keys
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_validation_scripts_updated_at
BEFORE UPDATE ON validation_scripts
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_data_contracts_updated_at
BEFORE UPDATE ON data_contracts
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_received_sequence_tracker_updated_at
BEFORE UPDATE ON received_sequence_tracker
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_pii_rules_updated_at
BEFORE UPDATE ON pii_rules
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_node_config_updated_at
BEFORE UPDATE ON node_config
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_node_certificates_updated_at
BEFORE UPDATE ON node_certificates
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Note: data_transfers and bulk_uploads tables typically do not have an updated_at trigger
-- as their status changes are often captured by specific status updates or end_time.
-- If a generic updated_at is needed, a trigger can be added.