# Transfer Architecture

## Governing Principle

The **receiver is the contract authority**.

In both async and sync transfers, the node that owns the data destination or the API service defines the contract — the schema, the governance rules, the PII handling policy, and who is permitted to participate. Senders and callers are *invited participants*; they do not author the terms.

This mirrors how data exchange works in practice: a data warehouse defines what it ingests, an API provider publishes what it exposes. Consumers agree to those terms or don't participate.

---

## Contract Model

### Who Creates a Contract

Only the **receiving node** creates a contract. There is no "Outgoing" direction — a contract is always defined from the receiver's perspective as Incoming. The Direction field is removed from the UI entirely.

### Who Participates

A contract is not bilateral. A single contract can have **multiple invited sender nodes**. Node B defines one loan eligibility contract and invites Node A, Node C, and Node D to participate under the same schema and governance rules.

```
data_contracts
  contract_id         (PK)
  name
  receiver_node_id    ← always the local node (the creator)
  interaction_type    async | sync
  schema_definition   JSON Schema or CSV field list
  metadata            format, governance_rules, sync_responder_url, sync_timeout_ms
  pii_fields[]
  status              Draft | Active | Suspended

contract_participants
  contract_id         → data_contracts.contract_id
  node_id             → partners.node_id   (invited sender)
  status              Invited | Active | Rejected
  invited_at
```

`sender_partner_id` and `receiver_partner_id` are removed from `data_contracts`. The receiver is always the local node. The set of authorised senders is `contract_participants` where `status = Active`.

### Contract Lifecycle

```
Receiver creates contract (Draft)
        ↓
Receiver invites one or more partner nodes
        ↓
Invitation sent to each partner via P2P (receive_contract_invitation)
        ↓
Each partner independently Accepts or Rejects
        ↓
Accepted partners appear in contract_participants with status = Active
        ↓
Any Active participant may initiate transfers / sync requests
```

The receiver can invite additional nodes at any time. Each invitation is independent — Node C rejecting does not affect Node A's participation.

---

## Async Transfer Flow

Node B (receiver) defines a contract specifying the data format and PII governance rules. Node A (an invited and accepted participant) uploads a file and initiates a transfer.

```
Node A                              Node B
  │                                   │
  │── receive_transfer_stream ───────▶│
  │   (file_data governed by          │── validate participant
  │    L1/L2 on Node A,               │── verify sequence number
  │    sequence_number attached)       │── apply L1/L2 governance
  │                                   │── persist governed payload
  │◀─ 200 OK ─────────────────────────│
```

On reception, Node B:
1. Verifies the sender is an Active participant in the contract
2. Verifies the sequence number (replay protection)
3. Stores the governed payload

---

## Sync Transfer Flow

Node B (receiver / API provider) defines a contract specifying the request schema, `sync_responder_url`, and timeout. Node A (an invited and accepted participant) sends a sync request.

```
Node A                              Node B
  │                                   │
  │── execute_sync_request ──────────▶│
  │   (request_payload governed       │── validate participant
  │    by L1/L2 on Node A)            │── apply L1/L2 governance to request
  │                                   │── forward to sync_responder_url
  │                                   │       ↓
  │                                   │   Internal Service (e.g. eligibility API)
  │                                   │       ↓
  │                                   │── apply L2 to response
  │◀─ response_payload ───────────────│
```

`sync_responder_url` is set by Node B when creating the contract. Node A never sees or configures it — it is not transmitted in the contract proposal. Node B's `receiveSyncRequest` reads it from its own local contract metadata.

---

## Authorisation Check

All inbound transfer and sync request handlers replace the old `sender_partner_id` equality check with a participant lookup:

```sql
SELECT 1 FROM contract_participants
WHERE contract_id = ? AND node_id = ? AND status = 'Active'
```

If the sender is not an Active participant, the request is rejected with HTTP 403.

---

## UI Changes

### Data Contracts Page

| Field | Before | After |
|---|---|---|
| Direction | Outgoing / Incoming dropdown | Removed |
| Partner | Single dropdown (one partner) | Multi-select — invite list |
| Sync Responder URL | Shown for all sync contracts | Shown only when creating (receiver configures it) |

The contract table gains an **Invited Nodes** column showing participant count and statuses.

### Initiate Transfer (transfers.html)

No change to the sender's initiation flow. Node A selects an active contract and uploads a file or enters a sync payload as before. The contract list only shows contracts where the local node is an Active participant.

---

## Stack Changes Required

### Database

- Remove `sender_partner_id`, `receiver_partner_id` from `data_contracts`
- Add `receiver_node_id` to `data_contracts` (always the local node at creation time)
- Add `contract_participants (contract_id, node_id, status, invited_at)` table
- Migration: existing bilateral contracts — promote `sender_partner_id` to a single row in `contract_participants`

### DataContract.java

| Function | Change |
|---|---|
| `create_contract` | Remove partner ID params; set `receiver_node_id` from local node config |
| `invite_node` | New — inserts a row into `contract_participants`, sends invitation P2P |
| `receive_contract_invitation` | New — replaces `receive_proposed_contract`; partner reviews and accepts/rejects |
| `accept_contract` | Updates `contract_participants.status` to Active for the accepting node |
| `reject_contract` | Updates `contract_participants.status` to Rejected |
| `propose_contract` | Removed — replaced by `invite_node` |

### TransferEngine.java / SyncEngine.java

- Replace `sender_partner_id` equality checks with `contract_participants` lookup
- `loadSyncContract` (caller side): join via `contract_participants` to resolve receiver FQDN
- `loadSyncContractReceiver`: validate sender against `contract_participants`

### Validation Schemas (.jschema)

- `create_contract.jschema`: remove `sender_partner_id`, `receiver_partner_id`; remove `direction`
- New `invite_node.jschema`
- New `receive_contract_invitation.jschema`

---

## What Does Not Change

- L1/L2 governance pipeline (`TransferEngine.applyGovernance`, `applyPiiOnly`)
- Replay protection (sequence numbers for async, nonce TTL for sync)
- Circuit breaker (SyncEngine)
- Audit logging
- The async file transfer mechanics (Base64, staging path, polling)
- mTLS / P2P handshake token

---

---

# Implementation Plan

Seven phases in dependency order. Each phase is independently testable before moving to the next.

---

## Phase 1 — Database Migration

**File:** `db/03_contract_participants.sql`

### 1.1 — Add `receiver_node_id` to `data_contracts`

```sql
ALTER TABLE data_contracts ADD COLUMN receiver_node_id uuid;
UPDATE data_contracts
SET receiver_node_id = (SELECT node_id FROM node_config LIMIT 1);
ALTER TABLE data_contracts ALTER COLUMN receiver_node_id SET NOT NULL;
```

Existing contracts were created by the local node, so the local `node_id` is the correct receiver for all rows.

### 1.2 — Create `contract_participants`

```sql
CREATE TABLE contract_participants (
    contract_id  uuid        NOT NULL REFERENCES data_contracts(contract_id) ON DELETE CASCADE,
    node_id      varchar     NOT NULL,
    status       varchar     NOT NULL DEFAULT 'Invited'
                             CHECK (status IN ('Invited', 'Active', 'Rejected')),
    invited_at   timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contract_id, node_id)
);
```

### 1.3 — Migrate existing bilateral contracts

```sql
INSERT INTO contract_participants (contract_id, node_id, status, invited_at)
SELECT contract_id, sender_partner_id, 'Active', updated_at
FROM data_contracts
WHERE sender_partner_id IS NOT NULL;
```

### 1.4 — Update `data_contracts` status vocabulary

Remove `Proposed` — contract-level status is now `Draft | Active | Suspended`. Per-participant status lives in `contract_participants`.

```sql
ALTER TABLE data_contracts
    DROP COLUMN sender_partner_id,
    DROP COLUMN receiver_partner_id,
    DROP COLUMN direction;
```

### 1.5 — Index for participant lookups

```sql
CREATE INDEX idx_contract_participants_node ON contract_participants(node_id, status);
```

---

## Phase 2 — DataContract.java

### 2.1 — `create_contract` (updated)

Remove `direction`, `sender_partner_id`, `receiver_partner_id` from the INSERT. Add `receiver_node_id` populated from `node_config`:

```sql
INSERT INTO data_contracts
  (contract_id, name, receiver_node_id, schema_definition, metadata,
   pii_fields, interaction_type, status, updated_at)
VALUES
  (?, ?, (SELECT node_id FROM node_config LIMIT 1), ?::jsonb, ?::jsonb, ?, ?, 'Draft', NOW())
```

### 2.2 — `invite_node` (new)

Input: `contract_id`, `node_id` (partner to invite).

Steps:
1. Insert into `contract_participants (contract_id, node_id, status='Invited')`
2. Load full contract from DB
3. Build invitation payload — **strip `sync_responder_url` from metadata before sending** (it is internal to the receiver and must never leave the node)
4. POST `receive_contract_invitation` to the partner's FQDN via P2P

```sql
INSERT INTO contract_participants (contract_id, node_id, status)
VALUES (?, ?, 'Invited')
ON CONFLICT (contract_id, node_id) DO NOTHING
```

### 2.3 — `receive_contract_invitation` (new, replaces `receive_proposed_contract`)

Called on the invited node when a partner sends an invitation.

Steps:
1. Upsert the contract into local `data_contracts` (status = `Draft`)
2. Insert local node into `contract_participants` with `status = 'Invited'`

The invited node now sees the contract in the UI and can Accept or Reject.

```sql
INSERT INTO data_contracts
  (contract_id, name, receiver_node_id, schema_definition, metadata,
   pii_fields, interaction_type, status, updated_at)
VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, 'Draft', NOW())
ON CONFLICT (contract_id) DO UPDATE
  SET status = 'Draft', updated_at = NOW();

INSERT INTO contract_participants (contract_id, node_id, status)
VALUES (?, (SELECT node_id FROM node_config LIMIT 1), 'Invited')
ON CONFLICT (contract_id, node_id) DO NOTHING;
```

### 2.4 — `accept_contract` (updated)

Steps:
1. Update local `contract_participants` row to `Active`
2. POST `confirm_invitation` P2P back to the contract's `receiver_node_id`

```sql
UPDATE contract_participants
SET status = 'Active'
WHERE contract_id = ? AND node_id = (SELECT node_id FROM node_config LIMIT 1)
```

### 2.5 — `reject_contract` (updated)

Steps:
1. Update local `contract_participants` row to `Rejected`
2. POST `decline_invitation` P2P back to the receiver

### 2.6 — `confirm_invitation` (new, P2P inbound)

Called on the receiver node when an invitee accepts.

```sql
UPDATE contract_participants SET status = 'Active'
WHERE contract_id = ? AND node_id = ?;

UPDATE data_contracts SET status = 'Active', updated_at = NOW()
WHERE contract_id = ? AND status = 'Draft';
```

### 2.7 — `decline_invitation` (new, P2P inbound)

Called on the receiver node when an invitee rejects.

```sql
UPDATE contract_participants SET status = 'Rejected'
WHERE contract_id = ? AND node_id = ?;
```

### 2.8 — `list_contracts` (updated)

Return contracts where local node is either the receiver or an active/invited participant:

```sql
SELECT dc.*,
  (dc.receiver_node_id = cfg.node_id) AS is_receiver,
  cp.status AS participant_status,
  (SELECT COUNT(*) FROM contract_participants
   WHERE contract_id = dc.contract_id AND status = 'Active') AS active_participant_count
FROM data_contracts dc
CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg
LEFT JOIN contract_participants cp
  ON cp.contract_id = dc.contract_id AND cp.node_id = cfg.node_id
WHERE dc.receiver_node_id = cfg.node_id
   OR cp.node_id IS NOT NULL
ORDER BY dc.updated_at DESC
```

### 2.9 — `get_contract` (updated)

Include participant list in the response:

```sql
SELECT node_id, status, invited_at
FROM contract_participants
WHERE contract_id = ?
ORDER BY invited_at
```

### 2.10 — Remove

- `propose_contract` — replaced by `invite_node`
- `receive_proposed_contract` — replaced by `receive_contract_invitation`
- `receive_status_update` — replaced by `confirm_invitation` / `decline_invitation`
- `query_contract_status` and `force_sync_status` — no longer needed; lifecycle is event-driven via P2P callbacks

---

## Phase 3 — TransferEngine.java

### 3.1 — `handleOutboundInitiation` in DXManager (updated)

The UI no longer supplies `receiver_node_id` — derive it from the contract:

```sql
SELECT receiver_node_id FROM data_contracts WHERE contract_id = ?
```

Remove `receiver_node_id` from the `initiate_transfer` input. Remove the Target Partner dropdown from `transfers.html` (Phase 6).

### 3.2 — `executeTransferSequence` (updated)

The join to resolve the receiver's FQDN changes from `receiver_partner_id` to `receiver_node_id`:

```sql
SELECT t.*, p.fqdn, cfg.storage_active_path,
       c.schema_definition, c.pii_fields, c.metadata AS contract_metadata
FROM data_transfers t
JOIN partners p ON t.receiver_node_id = p.node_id
JOIN data_contracts c ON t.contract_id = c.contract_id
CROSS JOIN (SELECT storage_active_path FROM node_config LIMIT 1) cfg
WHERE t.transfer_id = ?
```

`data_transfers` still carries `receiver_node_id` (the node the transfer is going to), so this change is minimal.

### 3.3 — `handleIncomingJsonTransfer` in DXManager (updated)

Add participant authorisation before processing:

```sql
SELECT 1 FROM contract_participants
WHERE contract_id = ? AND node_id = ? AND status = 'Active'
```

If no row found: respond HTTP 403 `Forbidden` — `Sender is not an authorised participant of this contract`.

---

## Phase 4 — SyncEngine.java

### 4.1 — `loadSyncContract` (caller side, updated)

Node A (participant) needs the receiver's FQDN and confirms its own participation:

```sql
SELECT c.receiver_node_id, c.schema_definition, c.metadata,
       c.interaction_type, c.status, p.fqdn, cfg.node_id AS local_node_id
FROM data_contracts c
JOIN partners p ON p.node_id = c.receiver_node_id
JOIN contract_participants cp
  ON cp.contract_id = c.contract_id
 AND cp.node_id = cfg.node_id
 AND cp.status = 'Active'
CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg
WHERE c.contract_id = ?
  AND c.interaction_type = 'sync'
  AND c.status = 'Active'
```

If no row: the contract either doesn't exist, isn't sync, isn't active, or the local node is not an active participant — throw with an appropriate message in each case.

### 4.2 — `loadSyncContractReceiver` (receiver side, updated)

Validate that the inbound sender is an active participant:

```sql
SELECT c.schema_definition, c.metadata, c.interaction_type, c.status,
       cfg.node_id AS local_node_id
FROM data_contracts c
CROSS JOIN (SELECT node_id FROM node_config LIMIT 1) cfg
WHERE c.contract_id = ?
  AND c.receiver_node_id = cfg.node_id
  AND EXISTS (
    SELECT 1 FROM contract_participants cp
    WHERE cp.contract_id = c.contract_id
      AND cp.node_id = ?          -- sender_node_id from the inbound request
      AND cp.status = 'Active'
  )
```

If no row: HTTP 403 — sender is not an authorised participant.

---

## Phase 5 — Validation Schemas (.jschema)

### 5.1 — `create_contract.jschema` (updated)

Remove: `direction`, `sender_partner_id`, `receiver_partner_id`.  
Keep: `_func`, `name`, `schema_definition`, `metadata`, `pii_fields`, `interaction_type`.

### 5.2 — `invite_node.jschema` (new)

```json
{
  "required": ["_func", "contract_id", "node_id"],
  "properties": {
    "_func":       { "type": "string", "const": "invite_node" },
    "contract_id": { "type": "string" },
    "node_id":     { "type": "string" }
  },
  "additionalProperties": false
}
```

### 5.3 — `receive_contract_invitation.jschema` (new)

```json
{
  "required": ["_func", "contract_id", "name", "schema_definition", "metadata", "sender_node_id"],
  "properties": {
    "_func":             { "type": "string", "const": "receive_contract_invitation" },
    "contract_id":       { "type": "string" },
    "name":              { "type": "string" },
    "sender_node_id":    { "type": "string" },
    "interaction_type":  { "type": "string", "enum": ["async", "sync"] },
    "schema_definition": { "type": "object", "additionalProperties": true },
    "metadata":          { "type": "object", "required": ["format"] },
    "pii_fields":        { "type": "array",  "items": { "type": "string" } }
  },
  "additionalProperties": false
}
```

### 5.4 — `confirm_invitation.jschema` and `decline_invitation.jschema` (new)

```json
{
  "required": ["_func", "contract_id", "node_id"],
  "properties": {
    "_func":       { "type": "string", "const": "confirm_invitation" },
    "contract_id": { "type": "string" },
    "node_id":     { "type": "string" }
  },
  "additionalProperties": false
}
```

`decline_invitation.jschema` is identical with `"const": "decline_invitation"`.

---

## Phase 6 — contracts.html

### 6.1 — Contract Wizard (Step 1)

- **Remove** Direction dropdown
- **Remove** Target Partner dropdown
- **Keep** Interaction Type, Sync fields (Responder URL, Timeout), Retention, Format
- After the contract is saved as Draft, the wizard closes and the contract row appears in the table with an **Invite** button

### 6.2 — Invite Flow (new)

On Draft contracts where local node is the receiver, show an **Invite Partners** button. Clicking it opens a modal with:
- Multi-select list of Active partners not yet invited
- Invite button — calls `invite_node` for each selected partner

### 6.3 — Contract Table

| Column | Change |
|---|---|
| Counterparty | Replace with **Participants** (count of Active / total invited) |
| Direction | Remove |
| Status | Keep — now reflects contract-level status (Draft / Active / Suspended) |
| Actions | **Invite** (receiver, Draft); **Accept / Reject** (participant, Invited); **Inspect** (all) |

### 6.4 — Contract Inspector

Add a **Participants** section listing each invited node, their status, and invited date.

---

## Phase 7 — transfers.html

### 7.1 — Initiation Modal

- **Remove** Target Partner dropdown entirely — receiver is determined by the selected contract
- Contract dropdown: populated only with Active contracts where local node is an Active participant (query `contract_participants`)
- `execute_sync_request` and `initiate_transfer` calls no longer include `receiver_node_id`

### 7.2 — `initiate_transfer.jschema` (updated)

Remove `receiver_node_id` from required fields and properties.

---

## Phase 8 — Testing Updates

### 8.1 — Apply migration on both nodes

```bash
docker exec -i node-a-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/03_contract_participants.sql

docker exec -i node-b-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/03_contract_participants.sql
```

### 8.2 — New test flow (replaces sync-test.md Step 3)

1. On **Node B** → Data Contracts → New Contract → set schema, interaction type, sync_responder_url → Register (saves as Draft)
2. On **Node B** → Invite → select Node A → Send Invitation
3. On **Node A** → Data Contracts → locate Invited contract → Accept
4. On **Node A** → Transfer Logs → Initiate Transfer → select contract → send payload
5. Verify in Sync Calls tab on both nodes

### 8.3 — Multi-participant test

Repeat Step 2 for Node C. Verify Node A and Node C can each independently initiate transfers against the same contract on Node B, and that audit logs on Node B correctly attribute each transfer to its sender.

### 8.4 — Authorisation rejection test

Attempt a transfer from a node that has not been invited. Verify HTTP 403 is returned and an audit entry is written.

---

## Delivery Order

| Phase | Deliverable | Depends on |
|---|---|---|
| 1 | `db/03_contract_participants.sql` | — |
| 2 | `DataContract.java` | Phase 1 |
| 3 | `DXManager.java`, `TransferEngine.java` | Phase 1 |
| 4 | `SyncEngine.java` | Phase 1 |
| 5 | `.jschema` files | Phase 2 |
| 6 | `contracts.html` | Phase 2, 5 |
| 7 | `transfers.html` | Phase 3, 4 |
| 8 | Testing + doc updates | All |
