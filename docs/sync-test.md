# Testing Sync Contracts and Transfers

The sync feature is fully implemented (SyncEngine, schema, UI). It requires the `02_sync_schema_changes.sql` migration to be applied on top of the base schema.

---

## Step 1 — Apply the Sync Schema Migration

The P2P setup runs `01_init.sql` automatically on first boot. Apply the sync migration manually to each running node's DB:

```bash
# Node A
docker exec -i node-a-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/02_sync_schema_changes.sql

# Node B
docker exec -i node-b-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/02_sync_schema_changes.sql
```

---

## Step 2 — Bootstrap Both Nodes

Follow steps 1–7 of `Local_Testing_Guide.md` — network, containers, certs, partner registration. Nothing changes here.

---

## Step 3 — Create a Sync Contract

On **Node A** (`http://localhost:8082`) → **Data Contracts → New Contract**:

- Partner: `NODE-B-NORTH`
- **Interaction Type: Sync** (radio toggle in the wizard)
- Direction: **Outgoing** (Node A is the caller)
- Set L1/L2 rules as desired
- Click **Register → Propose**

On **Node B** → locate the incoming proposal → **Accept**.

### Wizard Step 2 — JSON Schema Definition

Paste this into the **JSON Schema Definition** textarea in Step 2 of the wizard. Add `"x-pii": true` to any property that should be governed by the L1/L2 anonymisation engine — the wizard auto-detects these and carries them into Step 3 for rule assignment.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["customer_id", "mobile", "product"],
  "properties": {
    "customer_id": {
      "type": "string",
      "x-pii": true
    },
    "mobile": {
      "type": "string",
      "x-pii": true
    },
    "product": {
      "type": "string",
      "enum": ["loan", "credit_card", "insurance"]
    },
    "pincode": {
      "type": "string"
    }
  }
}
```

Step 3 will then list `customer_id` and `mobile` for anonymisation rule assignment (e.g. Hash, Mask, Tokenise).

> **Sync-specific fields (Step 1):** Set **Interaction Type** to `Sync`, enter `http://mock-responder:8099/eligibility` as the **Responder URL** (Node B only — this is the internal service Node B proxies requests to), and leave **Timeout** at `10000` ms. Docker Compose service names resolve within the same project network; `localhost` does not work here.

---

## Step 4 — Configure the Responder (on Node B)

### What is the mock-responder?

In a real deployment, the `sync_responder_url` points to an **internal service within the receiving organisation's network** — for example, a loan eligibility API, a fraud scoring engine, or a CRM lookup. When Node B receives a sync request from Node A, it validates and governs the payload, then proxies it to that internal service and returns the response back to Node A inline.

For local testing there is no real internal service, so `docker-compose.yml` includes a `mock-responder` — a minimal Python HTTP server that accepts any POST request and replies with `{"result":"ok"}`. This lets the full sync round-trip (Node A → Node B → internal service → Node B → Node A) be exercised without standing up a real backend.

The script lives at `test/mock_responder.py` and can be customised to return richer response payloads for more realistic testing.

### Starting the mock-responder

The service starts automatically when you bring up Node B:

```bash
docker compose -p node-b up -d
```

Verify it is reachable from inside the server container:

```bash
docker exec node-b-server-1 wget -qO- --post-data='{"test":1}' \
  --header='Content-Type: application/json' http://mock-responder:8099/eligibility
# Expected: {"result":"ok"}
```

### Why `mock-responder` and not `localhost`?

The mock runs as a **separate Docker Compose service**, not inside the `server` container. From inside the `server` container, `localhost` refers to the server container itself, not the mock. Docker Compose places all services in the same project network and makes them reachable by service name, so the correct URL is `http://mock-responder:8099/<path>`.

If you have an existing sync contract with `sync_responder_url` set to `localhost`, update it:

```bash
docker exec -i node-b-database-1 psql -U tsi_admin -d tsi_dx_node -c \
  "UPDATE data_contracts SET metadata = metadata || '{\"sync_responder_url\": \"http://mock-responder:8099/eligibility\"}'::jsonb WHERE interaction_type = 'sync';"
```

---

## Step 5 — Execute a Sync Request

### Via the UI

On **Node A** → **Transfer Logs → Initiate Transfer**:

- Select the sync contract — Step 3 switches to a JSON textarea instead of a file upload
- Enter a `request_payload` matching the contract's schema, e.g.:
  ```json
  { "customer_id": "C-001", "mobile": "9876543210", "product": "loan" }
  ```
- Optionally set an **Idempotency Key**
- Click **Send Request**
- The governed response payload appears inline in the modal

### Via the Client API

```bash
curl -s -X POST http://localhost:8082/api/client/dx \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-app-api-key>" \
  -d '{
    "_func": "execute_sync_request",
    "contract_id": "<uuid-of-sync-contract>",
    "request_payload": { "customer_id": "C-001", "mobile": "9876543210", "product": "loan" },
    "idempotency_key": "test-001"
  }'
```

Expected response:

```json
{ "success": true, "response_payload": { ... }, "duration_ms": 42 }
```

---

## Step 6 — Verify

| What to check | Where |
|---|---|
| Sync audit row on Node A (caller) | Transfer Logs → Sync Calls tab |
| Sync audit row on Node B (receiver) | Transfer Logs → Sync Calls tab |
| Sync Calls (24h) counter | Dashboard stat card |
| `interaction_type: sync` badge | Data Contracts list table |
| Audit event filter | Audit → Event Type: Sync Request |
| Contract Inspector | `get_contract_inspector` shows `interaction_type` and `timeout` |

---

## Replay Protection Test

Send the same `idempotency_key` twice within the nonce TTL window — the second call must be rejected. After the TTL expires (~30s default), a new call with a fresh nonce succeeds.

---

## Circuit Breaker Test

Take down the mock responder on Node B. Send 6 consecutive sync calls from Node A — the 6th should fail fast (circuit open) rather than waiting for the full timeout.

---

## Async Regression Test

Initiate a transfer over an `interaction_type: async` contract and confirm it still routes through `TransferEngine`, uses `receive_transfer_stream`, applies sequence-number replay protection, and logs to `data_transfers` as before. The sync lane must not affect async behaviour.

---

## Key Differences from Async Testing

| | Async | Sync |
|---|---|---|
| Transfer initiation | Upload file | POST JSON payload |
| Response | Queued (poll later) | Returned inline (HTTP 200) |
| Audit table | `data_transfers` | `sync_audit_log` |
| Replay protection | Sequence numbers | Nonce TTL (`sync_nonces` table) |
| Circuit breaker | None | Opens after 5 consecutive failures to same partner |
