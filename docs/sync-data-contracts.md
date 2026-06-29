# Extending TSI DX Node with Synchronous Data Contracts

**Status:** Proposal / Implementation Plan  
**Audience:** Platform and integration engineering  
**Scope:** Additive capability - no change to existing asynchronous flows

---

## Context

TSI DX Node governs asynchronous B2B data exchange through a contract-enforced, mTLS-secured pipeline with L1/L2 field-level governance and an immutable audit trail. A Business Correspondent integration is a mix of async batch flows (already governed) and synchronous real-time calls - eligibility checks, OTP, credit decisioning, balance inquiries - that currently ride bespoke REST APIs outside the governance fabric entirely.

This plan extends DX Node with a synchronous exchange lane that reuses every valuable piece of the existing platform (mTLS/PKI, node registry, L1/L2 contract engine, Contract Inspector, audit infrastructure) and adds only the mechanics unique to request/response: connection pooling, nonce-based replay protection, a live responder on the receiving side, and a synchronous audit log. The asynchronous pipeline is untouched.

---

## Architecture Overview

```
   Client API (push, batch)                 Sync API (request/response)   ← NEW entry
            │                                            │
            ▼                                            ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  SHARED FOUNDATION  (reused by both lanes, unchanged)         │
   │   mTLS + PKI  ·  Node registry  ·  Contracts L1/L2  · Inspector│
   └──────────────────────────────────────────────────────────────┘
            │                                            │
            ▼                                            ▼
   Async delivery engine                       Sync delivery engine     ← NEW
   (staging · replay · mirroring)              (pooled conn · correlation
        [UNCHANGED]                              · timeout · idempotency)
```

Both lanes pass through the same governance core; they diverge only at the delivery layer.

---

## What Is Reused vs. What Is New

### Reused unchanged

| File | Role |
|------|------|
| `src/.../framework/P2PClient.java` | mTLS HttpClient factory (extended for pooling, not replaced) |
| `src/.../framework/PKIUtil.java` | Certificate generation and validation |
| `src/.../api/admin/Partners.java` | Node registry + X.509 trust manager |
| `src/.../framework/JSONSchemaValidator.java` | L1 schema validation |
| `src/.../framework/InterceptingFilter.java` | P2P bypass header (`X-DX-P2P-HANDSHAKE: DX-P2P-PROTOCOL-V1`) |
| `src/.../api/admin/Audit.java` + `audit_logs` table | Audit infrastructure |

### Specific functions to reuse within changed files

- `TransferEngine.applyGovernance()`, `processJsonGovernance()`, `processCsvGovernance()`, `transformValue()` - L1/L2 pipeline; called by SyncEngine directly
- `P2PClient.build(Duration, Redirect)` - base factory; extended with a pool layer on top
- `DataContract.syncContractWithPartner()` / `handleInboundProposal()` - P2P contract sync; extended to carry the new `interaction_type` field

### Files to modify

- `db/02_sync_schema_changes.sql` ← **new file** (no changes to `01_init.sql`)
- `src/.../api/admin/DataContract.java` - persist/propagate `interaction_type`
- `src/.../api/admin/DXManager.java` - add `receive_sync_request` P2P handler
- `src/.../api/client/DX.java` - add `execute_sync_request` client function; extend `get_contract_inspector`
- `src/.../framework/P2PClient.java` - add `buildPooled()` with per-partner client cache

### New files

- `src/.../framework/SyncEngine.java` - synchronous delivery engine (caller + responder sides)

---

## Implementation Plan

### Phase 1 - Contract Model Extension

**`db/02_sync_schema_changes.sql`** - three additive changes, nothing in `01_init.sql` is touched:

```sql
-- 1. New column on data_contracts
ALTER TABLE data_contracts
  ADD COLUMN interaction_type VARCHAR(50) NOT NULL DEFAULT 'async';
-- Existing rows default to 'async'. Sync contracts set 'sync'.
-- metadata JSONB carries: sync_responder_url, sync_timeout_ms (no new columns needed)

-- 2. Nonce table for sync replay protection (TTL-based, replaces monotonic sequence)
CREATE TABLE sync_nonces (
    nonce_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id     UUID REFERENCES data_contracts(contract_id),
    nonce           VARCHAR(255) NOT NULL UNIQUE,
    idempotency_key VARCHAR(255),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX idx_sync_nonces_nonce   ON sync_nonces(nonce);
CREATE INDEX idx_sync_nonces_expires ON sync_nonces(expires_at);

-- 3. Immutable per-call audit log (async equivalent of the transfer log)
CREATE TABLE sync_audit_log (
    log_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id      UUID REFERENCES data_contracts(contract_id),
    idempotency_key  VARCHAR(255),
    request_payload  JSONB,   -- post-anonymisation snapshot
    response_payload JSONB,   -- post-anonymisation snapshot
    sender_node_id   VARCHAR(255),
    receiver_node_id VARCHAR(255),
    duration_ms      BIGINT,
    status           VARCHAR(50),  -- SUCCESS, TIMEOUT, ERROR
    error_detail     TEXT,
    timestamp        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**`DataContract.java`** - four targeted changes:
1. `createContract()` - read `interaction_type` from input JSON (`getOrDefault("interaction_type", "async")`), validate it is `"async"` or `"sync"`, persist to column.
2. `syncContractWithPartner()` - include `interaction_type` in the proposal JSON body sent to the partner.
3. `handleInboundProposal()` - extract and persist `interaction_type` from inbound proposal (the existing `ON CONFLICT … DO UPDATE` upsert covers this with one extra column).
4. `getContract()` and list - include `interaction_type` in the returned JSON object.

No routing changes; all existing contract functions (`propose_contract`, `accept_contract`, `reject_contract`, `query_contract_status`) carry through unchanged.

---

### Phase 2 - SyncEngine (new file)

**`src/org/tsicoop/dxnode/framework/SyncEngine.java`**

Singleton (same pattern as `TransferEngine.getInstance()`).

#### Caller side - `executeSyncRequest(UUID contractId, JSONObject requestPayload, String idempotencyKey)`

1. Load contract from DB; assert `interaction_type = 'sync'` and `status = 'Active'`.
2. Look up partner FQDN from `partners` table via `contract.receiver_partner_id`.
3. Apply L1/L2 governance to `requestPayload` via `TransferEngine.getInstance().applyGovernance()`.
4. Generate a UUID nonce; persist to `sync_nonces` with `expires_at = NOW() + timeout` (default 30 s, overridable via `metadata.sync_timeout_ms`).
5. POST to `{partnerFqdn}/api/admin/transfers` using a pooled mTLS client with body:
   ```json
   {
     "_func": "receive_sync_request",
     "contract_id": "...",
     "nonce": "...",
     "idempotency_key": "...",
     "sender_node_id": "...",
     "request_payload": { ... }
   }
   ```
   Header: `X-DX-P2P-HANDSHAKE: DX-P2P-PROTOCOL-V1`
6. On HTTP 200: apply L1/L2 governance to `response_payload` in the returned JSON.
7. Write one row to `sync_audit_log` (request + response post-anonymisation, duration, status).
8. On timeout or non-200: write `sync_audit_log` row with `status = TIMEOUT/ERROR`; increment per-partner failure counter for circuit breaker; propagate exception.

**Circuit breaker:** A `ConcurrentHashMap<String, AtomicInteger>` per partner FQDN tracking consecutive failures. Open after 5 consecutive failures; reset after 60 s cooldown. Throw `ServiceUnavailableException` when open.

#### Receiver side - `receiveSyncRequest(JSONObject input, HttpServletResponse res)`

1. Extract `contract_id`, `nonce`, `idempotency_key`, `request_payload`.
2. Load sync contract; verify `status = 'Active'`.
3. **Nonce check:** `SELECT 1 FROM sync_nonces WHERE nonce = ? AND expires_at > NOW()`. If found, reject (replayed). If not found, insert (claim the nonce window).
4. Apply L1/L2 governance to inbound `request_payload`.
5. `POST` governed payload to `metadata.sync_responder_url` via a plain `HttpClient` (internal, no mTLS - stays within the node's trust boundary).
6. Apply L1/L2 governance to the responder's response body.
7. Write `sync_audit_log` row.
8. Return `{ "success": true, "response_payload": { ... } }` to caller.

---

### Phase 3 - DXManager.java

In the `_func` dispatch switch in `handleIncomingJsonTransfer()`, add one case:

```java
case "receive_sync_request":
    SyncEngine.getInstance().receiveSyncRequest(input, res, req);
    return;
```

The existing `receive_transfer_stream` case and all other cases are untouched.

Log `SYNC_REQUEST_RECEIVED` / `SYNC_REQUEST_FAILED` events via the existing `logAudit()` helper.

---

### Phase 4 - DX.java (Client API)

**New `_func`: `execute_sync_request`**

Input:
```json
{ "contract_id": "uuid", "request_payload": { ... }, "idempotency_key": "optional" }
```

Apply the same RBAC gate already used by `initiate_transfer`:
```sql
SELECT 1 FROM app_contracts WHERE app_id = ? AND contract_id = ?
```

Call `SyncEngine.getInstance().executeSyncRequest(contractId, payload, idempotencyKey)`.

Return:
```json
{ "success": true, "response_payload": { ... }, "duration_ms": 42 }
```

**Extend `get_contract_inspector`:** Include `interaction_type` in the returned contract object. For sync contracts, also surface `sync_responder_url` and `sync_timeout_ms` from the metadata JSONB - mask `sync_responder_url` on the sender-side view since it is the partner's internal address.

---

### Phase 5 - P2PClient.java (Connection Pooling)

Add a static `ConcurrentHashMap<String, HttpClient> POOL` and a new factory method:

```java
public static HttpClient buildPooled(String partnerFqdn, Duration timeout) {
    return POOL.computeIfAbsent(partnerFqdn, k -> build(timeout));
}
```

`SyncEngine` calls `buildPooled()`; `TransferEngine` continues calling `build()` as today. Java's `HttpClient` multiplexes connections over HTTP/2 by default, so the pooled client naturally keeps the mTLS session alive across calls.

---

## UI Changes

The frontend is plain HTML5 + vanilla JavaScript (Tailwind CSS). No new pages are needed - all changes fit within existing screens.

### `contracts.html` - 3 changes

**1. Creation wizard Step 1 - new "Interaction Type" field**
After the Direction dropdown, add a radio/toggle: `Async (Batch)` | `Sync (Request/Response)`. When Sync is selected, reveal two additional fields:
- **Responder URL** - the internal service endpoint the receiving node will proxy to (shown only when Direction = Incoming, since it is the receiver's concern); stored in `metadata.sync_responder_url`
- **Timeout (ms)** - defaults to 10 000; stored in `metadata.sync_timeout_ms`

Step 3 (Anonymization) is unchanged - L1/L2 rules apply identically to sync contracts.

**2. Contract list table - new "Interaction" column**
Add a badge column alongside the existing Format badge showing `Async` (grey) or `Sync` (blue) from `interaction_type`.

**3. Contract Inspector modal - sync-aware display**
Add an `interaction_type` row to the inspector header section. For sync contracts, surface `Timeout` and (on the receiver's view) `Responder URL`. The governance field table renders identically to async contracts.

---

### `transfers.html` - 2 changes

**4. New "Sync Calls" tab**
The existing tabs (All Exchanges / Pending / Completed / Failed) read from `data_transfers`. Add a **Sync Calls** tab that reads from `sync_audit_log` with columns:

| Timestamp | Counterparty | Contract | Duration (ms) | Status | Inspect |

The inspect action opens request + response payloads side-by-side in the existing dark-themed code viewer modal.

**5. Initiation modal - sync-aware flow**
When a sync contract is selected in the contract dropdown, replace the Step 3 "Upload File" step with:
- A JSON textarea labelled **Request Payload**
- An optional **Idempotency Key** text input
- Submit button label changes to "Send Request"
- On success: display the response payload inline in the modal before closing (unlike async, which queues and closes immediately)

---

### `audit.html` - 1 change

**6. Event Type filter - new sync category**
Add **Sync Request** to the existing event-type dropdown so users can filter to `SYNC_REQUEST_RECEIVED` / `SYNC_REQUEST_FAILED` events.

---

### `dashboard.html` - 1 change

**7. Stats grid - new "Sync Calls (24h)" stat card**
Add a **Sync Calls (24h)** card reading from `sync_audit_log WHERE timestamp > NOW() - INTERVAL '24h'`, alongside the existing Transfers (24h) card.

---

### `WEB-INF/validator/` - 2 new schema files

- `execute_sync_request.jschema` - validates `contract_id` (required UUID), `request_payload` (required object), `idempotency_key` (optional string)
- `list_sync_audit_logs.jschema` - validates filter params for the Sync Calls tab query

---

### UI changes summary

| File | Change |
|------|--------|
| `contracts.html` | Wizard Step 1 new fields; list table new badge column; Inspector modal new rows |
| `transfers.html` | New "Sync Calls" tab + sync-aware initiation modal |
| `audit.html` | New event-type filter option |
| `dashboard.html` | New stat card |
| `WEB-INF/validator/execute_sync_request.jschema` | New file |
| `WEB-INF/validator/list_sync_audit_logs.jschema` | New file |

---

## Design Guardrails

- **Async is untouched.** The synchronous lane is a new contract type with its own delivery engine; the existing single-package / replay / mirroring pipeline is not modified.
- **Opt-in per contract.** A contract declares its `interaction_type`; routing dispatches to the correct engine. Existing contracts continue unchanged.
- **Keep PII-heavy bulk on async.** Sync is for genuinely interactive calls (eligibility, OTP, balance, decisioning). Large PII datasets stay on the async lane.
- **No sync blind spots.** A sync audit log entry is mandatory for every call - parity with the transfer log is a requirement, not optional.
- **L2 on sync is a conscious choice.** Contracting parties that enable L2 tokenisation on a sync call accept the latency trade-off explicitly; the lane targets API-parity SLA regardless.

---

## Compliance Rationale

Because L1 and L2 contracts apply to both request and response payloads, the synchronous lane inherits:

- **Field-level anonymisation on real-time calls** - e.g. masking a mobile number on an OTP request or tokenising a customer identifier on an eligibility check, enforced on the wire rather than hoped-for in application code.
- **Contract Inspector visibility** showing a compliance officer exactly which fields are governed on the synchronous link, matching the legal agreement.
- **An immutable, per-call evidence trail** to demonstrate accountability under DPDP Rules (notified November 2025, substantive provisions effective mid-May 2027).

---

## Phased Delivery

| Phase | What Ships | Gate to Next Phase |
|-------|-----------|-------------------|
| 1 | `02_sync_schema_changes.sql` + DataContract.java changes | Existing async contracts still work; sync contracts can be created and proposed |
| 2 | SyncEngine.java + DXManager.java receiver + DX.java `execute_sync_request` | End-to-end sync call on a stateless, non-PII contract (e.g. serviceability check) |
| 3 | P2PClient.java pooling + Inspector rendering for sync contracts | Latency under load acceptable; compliance officer can see sync contracts in Inspector |
| 4 | Pilot one PII-bearing sync call (eligibility or OTP) | Latency floor measured; L2 tokenisation on sync path validated with partner |
| 5 | Circuit breaker hardening, idempotency caching, remaining sync BC processes | Full production readiness |

---

## Verification

### End-to-end (docker-compose, two nodes)

1. Start both nodes. Create a sync contract on node A with `interaction_type: "sync"`, set `metadata.sync_responder_url` to a mock HTTP endpoint on node B's internal address.
2. Register a client app on node A, bind it to the sync contract via `/api/admin/apps`.
3. Call `POST /api/client/dx` with `_func: "execute_sync_request"`.
4. Assert: HTTP 200, governed `response_payload` returned, one row in `sync_audit_log` on both nodes.
5. Call `get_contract_inspector` - verify `interaction_type: "sync"` appears.

### Replay protection

Send the same nonce twice within the TTL window - second call must be rejected. Send after TTL expiry - new call with a new nonce succeeds.

### Async regression

Initiate an async transfer over an `interaction_type: 'async'` contract - verify it still routes through `TransferEngine`, `receive_transfer_stream`, sequence-number replay protection, and `data_transfers` log exactly as before.

### Circuit breaker

Take down the mock responder. Send 6 consecutive sync calls - the 6th should fail fast (circuit open) rather than waiting for the full timeout.
