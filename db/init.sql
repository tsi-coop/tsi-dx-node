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

-- 1. `node_config` Table (Added for NodeManagement class)
-- Stores the single configuration entry for the local DX Node.
CREATE TABLE node_config (
    config_id UUID PRIMARY KEY DEFAULT '00000000-0000-0000-0000-000000000001', -- Singleton ID
    node_id VARCHAR(255) NOT NULL UNIQUE,
    about TEXT NULL,
    fqdn VARCHAR(255) NOT NULL UNIQUE,
    network_port INT NOT NULL,
    storage_active_path TEXT NOT NULL,
    storage_archive_path TEXT NOT NULL,
    logging_level VARCHAR(50) NOT NULL DEFAULT 'INFO', -- e.g., INFO, DEBUG, ERROR
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 2. `node_certificates` Table (Added for NodeManagement class to store PKI assets)
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

-- 3. `partners` Table
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

-- 4. `roles` Table
-- Defines different roles within the Admin App.
CREATE TABLE roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NULL,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 5. `users` Table
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

-- 6. `data_contracts` Table
-- Defines the agreements for data exchange between partners.
CREATE TABLE IF NOT EXISTS data_contracts (
    contract_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT NULL,
    -- Changed from UUID to VARCHAR to support Node IDs (Local & Remote)
    sender_partner_id VARCHAR(255) NOT NULL,
    receiver_partner_id VARCHAR(255) NOT NULL,
    schema_definition JSONB NOT NULL,
    metadata JSONB NULL, 
    retention_policy_days INT NULL,
    pii_fields TEXT[] NULL,
    direction VARCHAR(50),
    schema_json JSONB,
    governance_json JSONB,
    status VARCHAR(50) NOT NULL DEFAULT 'Draft',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for data_contracts table
CREATE INDEX idx_data_contracts_sender_partner_id ON data_contracts (sender_partner_id);
CREATE INDEX idx_data_contracts_receiver_partner_id ON data_contracts (receiver_partner_id);

-- 7. `apps` Table
-- REVISED: Ensure updated_at exists for the trigger
CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 8. `api_keys` Table
-- REVISED: Explicitly added updated_at to resolve "record new has no field" error
CREATE TABLE api_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key VARCHAR(255) NOT NULL UNIQUE,
    api_secret_hash VARCHAR(255) NOT NULL,
    app_id UUID NULL REFERENCES apps(id) ON DELETE SET NULL,     
    status VARCHAR(50) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NULL,
    last_used_at TIMESTAMP WITH TIME ZONE NULL
);

-- 9. `app_contracts` Table
-- Intersect table to define which apps have access to which data contracts.
CREATE TABLE IF NOT EXISTS app_contracts (
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    contract_id UUID NOT NULL REFERENCES data_contracts(contract_id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (app_id, contract_id)
);

-- Index for checking API authorization during transfer
CREATE INDEX idx_app_contracts_lookup ON app_contracts(app_id, contract_id);

-- 10. `data_transfers` Table
-- Records details of each data transfer event.
CREATE TABLE IF NOT EXISTS data_transfers (
    transfer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
    local_file_path TEXT NULL, 
    initiated_by_user_id UUID NULL REFERENCES users(user_id) ON DELETE SET NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    end_time TIMESTAMP WITH TIME ZONE NULL,
    retention_status VARCHAR(50) NOT NULL DEFAULT 'Active', -- 'Active', 'Archived', 'Purged'
    archived_at TIMESTAMP WITH TIME ZONE NULL,
    purged_at TIMESTAMP WITH TIME ZONE NULL
);

-- Essential Performance Indexes
-- Index for background RetentionEngine polling 
CREATE INDEX idx_transfers_retention_lookup ON data_transfers (retention_status, end_time) WHERE (status = 'Delivered' OR status = 'Received');
-- Index for Dashboard 'Recent Transfers' and 'Transfers (24h)' metrics
CREATE INDEX idx_transfers_dashboard_recent ON data_transfers (start_time DESC);
-- Index for filtering by Partner Node ID in the Transfer Monitoring UI
CREATE INDEX idx_transfers_partner_lookup ON data_transfers (sender_node_id, receiver_node_id);
-- Foreign key index for Data Contract correlation
CREATE INDEX idx_transfers_contract_id ON data_transfers (contract_id);
-- Index for status-based UI filtering (All/Pending/Completed/Failed tabs)
CREATE INDEX idx_transfers_status ON data_transfers (status);

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

-- 12. `pii_rules` Table
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

CREATE TRIGGER update_apps_updated_at 
BEFORE UPDATE ON apps
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at
BEFORE UPDATE ON api_keys
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_data_contracts_updated_at
BEFORE UPDATE ON data_contracts
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

-- Note: data_transfers do not have an updated_at trigger
-- as their status changes are often captured by specific status updates or end_time.
-- If a generic updated_at is needed, a trigger can be added.

-- Insert the default 'Administrator' role
INSERT INTO roles (role_id, name, description, is_system_role)
VALUES (
    'a0000000-0000-0000-0000-000000000001', -- A well-known UUID for the Administrator role
    'Administrator',
    'Full access to all TSI DX Node administrative functions.',
    TRUE -- This is a system-defined role
)
ON CONFLICT (role_id) DO NOTHING; -- Prevents errors if script is run multiple times

-- Insert the default 'Administrator' role
INSERT INTO roles (role_id, name, description, is_system_role)
VALUES (
    'a0000000-0000-0000-0000-000000000002', -- A well-known UUID for the Administrator role
    'Operator',
    'Ability to define data contracts & initiate transfers.',
    TRUE -- This is a system-defined role
)
ON CONFLICT (role_id) DO NOTHING; -- Prevents errors if script is run multiple times

