# Local P2P Testing Guide

This guide walks through running two fully independent TSI DX Node instances (Node A and Node B) on a single development machine, then testing both async batch transfers and synchronous request/response exchanges under the receiver-authority contract model.

---

## Architecture

| Component | Details |
|---|---|
| Node A | `node-a-server-1` · Host: `8082` (HTTP UI) · `8443` (HTTPS/P2P) |
| Node B | `node-b-server-1` · Host: `8083` (HTTP UI) · `9443` (HTTPS/P2P, host only) |
| Shared Network | `tsi-p2p-net` (external Docker bridge) |
| Node A DB | `node-a-database-1` · Host: `5434` |
| Node B DB | `node-b-database-1` · Host: `5435` |

> **Port note:** Both nodes run Jetty HTTPS on container port **8443**. The host exposes Node A's P2P port as `8443` and Node B's as `9443` to avoid collision. Container-to-container traffic always uses port `8443` directly — the host mapping is irrelevant for P2P.

---

## TLS Architecture

Jetty serves two connectors per container:

| Connector | Port | Protocol | Used by |
|---|---|---|---|
| HTTP | 8080 | Plain HTTP | Browser UI (via APP_PORT_MAP) |
| HTTPS | 8443 | TLS (dev self-signed cert) | P2P handshakes and mTLS |

The dev keystore is baked into the image at build time (`keytool`, self-signed). It handles **transport encryption only** — it is not the node's identity cert. The identity cert (generated in step 6) is stored in the database and loaded at runtime by `Partners.java` for the application-layer mTLS validation.

Partners.java's fallback client (trust-all) is used for the initial bootstrap handshake, so the self-signed transport cert does not block the first exchange. Once identity certs are registered, the genuine mTLS client takes over and validates peer certificates from the database trust store.

---

## 1. Required Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Base compose file (production) — no changes required |
| `docker-compose.p2p.yml` | P2P overlay — adds shared network and HTTPS port |
| `.env.node-a` | Environment variables for Node A |
| `.env.node-b` | Environment variables for Node B |

---

## 2. docker-compose.p2p.yml

Save this alongside `docker-compose.yml` in the project root. It is never used standalone.

```yaml
# docker-compose.p2p.yml
# Local P2P testing overlay — combine with docker-compose.yml via -f flag.
#
# PRE-REQUISITE:
#   docker network create tsi-p2p-net
#
# USAGE — Node A:
#   docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
#     --project-name node-a --env-file .env.node-a up --build -d
#
# USAGE — Node B:
#   docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
#     --project-name node-b --env-file .env.node-b up --build -d

services:

  server:
    ports:
      # APP_PORT_MAP differs per node (.env.node-a=8082:8080 / .env.node-b=8083:8080)
      - "${APP_PORT_MAP:-8082:8080}"
      # P2P_PORT_MAP exposes the HTTPS/mTLS port on the host, maps to Jetty HTTPS 8443
      # (.env.node-a=8443:8443 / .env.node-b=9443:8443)
      - "${P2P_PORT_MAP:-8443:8443}"
    networks:
      - default      # retains connectivity to database service
      - tsi-p2p-net  # peer-to-peer discovery network

  database:
    # Database stays on default network only — not exposed to the peer network
    networks:
      - default

networks:
  tsi-p2p-net:
    external: true
```

---

## 3. Environment Files

**.env.node-a**

```env
POSTGRES_DB=tsi_dx_node
POSTGRES_USER=tsi_admin
POSTGRES_PASSWD=secure_dev_password
DB_PORT_MAP=5434:5432
APP_PORT_MAP=8082:8080
P2P_PORT_MAP=8443:8443
TSI_DX_NODE_ENV=development
TSI_PRIVACY_VAULT_JWT_SECRET=node_a_secret_32_chars_long_here_
```

**.env.node-b**

```env
POSTGRES_DB=tsi_dx_node
POSTGRES_USER=tsi_admin
POSTGRES_PASSWD=secure_dev_password
DB_PORT_MAP=5435:5432
APP_PORT_MAP=8083:8080
P2P_PORT_MAP=9443:8443
TSI_DX_NODE_ENV=development
TSI_PRIVACY_VAULT_JWT_SECRET=node_b_secret_32_chars_long_here_
```

> **Note:** Both nodes use the same `POSTGRES_DB` name. Because each runs under a different `--project-name`, their volumes are automatically isolated as `node-a_postgres_data` and `node-b_postgres_data`.

---

## 4. Environment Setup

### 4.1 Create the Shared Network

Run this once before the first launch. The network persists across container restarts.

```bash
docker network create tsi-p2p-net
```

### 4.2 Start Node A

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.p2p.yml \
  --project-name node-a \
  --env-file .env.node-a \
  up --build -d
```

### 4.3 Start Node B

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.p2p.yml \
  --project-name node-b \
  --env-file .env.node-b \
  up --build -d
```

### 4.4 Verify Containers

```bash
docker ps --format "table {{.Names}}\t{{.Ports}}"
```

Expected output:

```
NAMES                  PORTS
node-b-server-1        0.0.0.0:8083->8080/tcp, 0.0.0.0:9443->8443/tcp
node-a-server-1        0.0.0.0:8082->8080/tcp, 0.0.0.0:8443->8443/tcp
node-a-database-1      0.0.0.0:5434->5432/tcp
node-b-database-1      0.0.0.0:5435->5432/tcp
```

### 4.5 Verify P2P Connectivity

Confirm Node A can reach Node B over the shared Docker network via HTTPS:

```bash
docker exec node-a-server-1 curl -sk \
  https://node-b-server-1:8443/api/admin/partners \
  -H "X-DX-P2P-HANDSHAKE: DX-P2P-PROTOCOL-V1" \
  -H "X-DX-FUNCTION: probe" \
  -d '{"_func":"probe"}'
```

> The `-k` flag skips certificate verification for the dev self-signed transport cert. The application-layer mTLS validation is handled separately by `Partners.java`.

Expected response:

```json
{"success":true,"status":"online"}
```

---

## 5. Node Bootstrapping

Initialize the identity for each node via the web UI. Use the Docker service hostname as the FQDN and **always use port `8443`** — that is the internal Jetty HTTPS port that all P2P traffic uses, regardless of what host port the node is exposed on.

> **Warning:** When prompted for "Public FQDN", enter the Docker service hostname (e.g. `node-a-server-1`), NOT your machine's LAN IP or `localhost`. The P2P handshake resolves hostnames over `tsi-p2p-net`. Using `localhost` would make the node advertise itself as the partner's own loopback address.

### Bootstrap Node A

Open `http://localhost:8082/init.html`

| Field | Value |
|---|---|
| Node ID | `NODE-A-SOUTH` |
| Public FQDN | `node-a-server-1` |
| mTLS Port | `8443` |

Click **Establish Node Authority**.

### Bootstrap Node B

Open `http://localhost:8083/init.html`

| Field | Value |
|---|---|
| Node ID | `NODE-B-NORTH` |
| Public FQDN | `node-b-server-1` |
| mTLS Port | `8443` |

Click **Establish Node Authority**.

> **Why `8443` for both?** The mTLS port is the port *this node tells its partners to use* when calling back. Container-to-container, both nodes listen on `8443` (Jetty HTTPS). The host-side port `9443` for Node B is only for browser/curl access from your dev machine — it is not used in container-to-container handshakes.

---

## 6. Sovereign Identity Generation (Private CA)

Generate self-signed certificates for each node. The Java backend requires private keys in PKCS#8 format.

### 6.1 Node A Identity

```bash
# Generate raw private key
openssl genrsa -out node_a_raw.key 2048

# Convert to PKCS#8 (required by Java backend)
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in node_a_raw.key -out node_a.key

# Self-signed certificate — use node-a-server-1 as Common Name when prompted
openssl req -new -x509 -key node_a.key -out node_a.crt -days 365

# Convert to PEM registry format
openssl x509 -in node_a.crt -out node_a.pem -outform PEM
```

### 6.2 Node B Identity

```bash
openssl genrsa -out node_b_raw.key 2048

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in node_b_raw.key -out node_b.key

# Use node-b-server-1 as Common Name when prompted
openssl req -new -x509 -key node_b.key -out node_b.crt -days 365

openssl x509 -in node_b.crt -out node_b.pem -outform PEM
```

### 6.3 Activate Identity in the UI

On each node, navigate to **Configuration → Node Settings → Import Signed Cert**.

| Node | Certificate Block (PEM) | Private Key Block (PEM) |
|---|---|---|
| Node A | Paste contents of `node_a.pem` | Paste contents of `node_a.key` |
| Node B | Paste contents of `node_b.pem` | Paste contents of `node_b.key` |

Click **Activate** on each node to bind the cryptographic identity to the protocol engine.

---

## 7. Mutual Trust Exchange

Both nodes must pre-register each other's public key before the P2P handshake will succeed.

### Phase 1 — Register Node B in Node A

On Node A (`http://localhost:8082`): **Partner Nodes → Add Partner**

| Field | Value |
|---|---|
| Node ID | `NODE-B-NORTH` |
| Host | `node-b-server-1` |
| Port | `8443` |
| Public Key | Upload `node_b.pem` |

### Phase 2 — Register Node A in Node B

On Node B (`http://localhost:8083`): **Partner Nodes → Add Partner**

| Field | Value |
|---|---|
| Node ID | `NODE-A-SOUTH` |
| Host | `node-a-server-1` |
| Port | `8443` |
| Public Key | Upload `node_a.pem` |

> **Important:** Use port `8443` for both registrations — not `9443`. The FQDN stored here (`node-b-server-1:8443`) is used directly for container-to-container calls. Port `9443` only exists on the host, not inside Node B's container.

> **Tip:** After registration, click **Sync Identity** on each partner entry. Status should change from `Pending` → `Active` on both nodes.

---

## 8. Database Migrations

The `docker-compose.yml` mounts the `db/` directory to `/docker-entrypoint-initdb.d`. On a clean database (empty volume), Postgres automatically runs all three files in order on first boot — no manual steps needed.

| Migration | What it creates |
|---|---|
| `01_init.sql` | Core schema — nodes, partners, contracts, transfers, audit logs |
| `02_sync_schema_changes.sql` | `sync_nonces`, `sync_audit_log` tables for synchronous contracts |
| `03_contract_participants.sql` | `contract_participants` table, `receiver_node_id` on `data_contracts`, removes legacy `direction`/`sender_partner_id`/`receiver_partner_id` columns |

**Upgrading an existing node** (volume already has data): apply the new migrations manually instead of wiping the volume:

```bash
# Node A
docker exec -i node-a-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/02_sync_schema_changes.sql
docker exec -i node-a-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/03_contract_participants.sql

# Node B
docker exec -i node-b-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/02_sync_schema_changes.sql
docker exec -i node-b-database-1 psql -U tsi_admin -d tsi_dx_node \
  < db/03_contract_participants.sql
```

---

## 9. Contract Model — Receiver Authority

Only the **receiving node** creates contracts. The receiver invites one or more partner nodes to participate. Each invited node can Accept or Reject. Transfers — async or sync — can only be initiated by nodes with an `Active` participant row.

```
Node B (Receiver)          Node A (Participant)
──────────────────         ────────────────────
New Contract (Draft)
       │
  Invite Node A ──────────► receive_contract_invitation
                                     │
                             Accept/Reject
                                     │
       ◄──────────────── confirm_invitation / decline_invitation
       │
  Contract → Active
                             Transfer Logs → Initiate Transfer
                                     │
                             ──────────────────────────►
                             async: receive_transfer_stream
                             sync:  receive_sync_request
```

---

## 10. Async Batch Transfer

Async transfers send a JSON or CSV file from a participant (Node A) to the receiver (Node B). The payload is governed by L1 schema validation and L2 PII anonymisation before dispatch.

### 10.1 Create an Async Contract on Node B

On **Node B** (`http://localhost:8083`) → **Data Contracts → New Contract**:

- **Contract Name:** `Weekly Loan Applications`
- **Data Format:** JSON
- **Interaction Type:** Async (Batch Transfer)
- **Retention Policy:** 30 days

Click **Register Contract**. The contract is saved as Draft, owned by Node B.

**JSON Schema Definition** (paste in Step 2 of the wizard):

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["applicant_id", "mobile", "product", "amount"],
  "properties": {
    "applicant_id": { "type": "string", "x-pii": true },
    "mobile":       { "type": "string", "x-pii": true },
    "product":      { "type": "string", "enum": ["loan", "credit_card", "insurance"] },
    "amount":       { "type": "number" },
    "pincode":      { "type": "string" }
  }
}
```

In Step 3, assign PII rules for `applicant_id` and `mobile` (e.g. Hash, Mask, Tokenise).

### 10.2 Invite Node A

On **Node B** → Data Contracts → `Weekly Loan Applications` → **Invite** → select **Node A** → **Send Invitations**.

### 10.3 Accept on Node A

On **Node A** (`http://localhost:8082`) → **Data Contracts** → locate `Weekly Loan Applications` (status: Invited) → **Accept**.

Node A transitions to Active participant. Node B's contract transitions to Active.

### 10.4 Initiate a Transfer from Node A

**Via the UI:** Node A → **Transfer Logs → Initiate Transfer** → select `Weekly Loan Applications [ASYNC]` → upload a JSON file → **Upload & Start**.

Sample payload (save as `test_payload.json`):

```json
{
  "applicant_id": "A-1001",
  "mobile": "9876543210",
  "product": "loan",
  "amount": 250000
}
```

**Via curl:**

```bash
B64=$(base64 -w 0 test_payload.json)

curl -s -X POST http://localhost:8082/api/admin/transfers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-admin-token>" \
  -d "{
    \"_func\": \"initiate_transfer\",
    \"contract_id\": \"<uuid-of-async-contract>\",
    \"file_name\": \"test_payload.json\",
    \"file_data\": \"$B64\",
    \"file_size\": $(wc -c < test_payload.json)
  }"
```

Expected: `{ "success": true, "transfer_id": "..." }`

### 10.5 Verify

| Check | Where |
|---|---|
| Status: Delivered | Node A → Transfer Logs → All Exchanges |
| Status: Received | Node B → Transfer Logs → All Exchanges |
| PII fields transformed | Node B → Transfer Logs → View File — `applicant_id` and `mobile` anonymised |
| TRANSFER audit events | Both nodes → Audit Trail |
| Sequence increments | Send a second file — monotonicity enforced |

---

## 11. Sync Request / Response Transfer

Sync transfers send a JSON payload from Node A and receive an inline response from an internal service running behind Node B. L1+L2 governance is applied to the request; L2-only to the response.

### 11.1 Start the Mock Responder on Node B

The mock responder starts automatically with Node B:

```bash
docker compose -p node-b up -d
```

Verify it is reachable from inside the Node B server container:

```bash
docker exec node-b-server-1 wget -qO- --post-data='{"test":1}' \
  --header='Content-Type: application/json' http://mock-responder:8099/eligibility
# Expected: {"result":"ok"}
```

**What is the mock responder?** In a real deployment, `sync_responder_url` points to an internal service — a loan eligibility engine, a fraud scoring API, a CRM lookup. When Node B receives a sync request, it governs the payload and proxies it to that internal service, returning the response inline to Node A. The `mock-responder` service in `docker-compose.yml` (defined in `test/mock_responder.py`) provides a stand-in that accepts any POST and replies `{"result":"ok"}`.

> **Why `mock-responder` and not `localhost`?** The mock runs as a separate Docker Compose service. From inside the `server` container, `localhost` refers only to that container. Docker Compose places all services in the same project network and makes them reachable by service name.

If you have an existing sync contract with `sync_responder_url` pointing to `localhost`, update it:

```bash
docker exec -i node-b-database-1 psql -U tsi_admin -d tsi_dx_node -c \
  "UPDATE data_contracts
   SET metadata = metadata || '{\"sync_responder_url\": \"http://mock-responder:8099/eligibility\"}'::jsonb
   WHERE interaction_type = 'sync';"
```

### 11.2 Create a Sync Contract on Node B

On **Node B** → **Data Contracts → New Contract**:

- **Contract Name:** `Loan Eligibility Check`
- **Data Format:** JSON
- **Interaction Type:** Sync (Request / Response)
- **Responder URL:** `http://mock-responder:8099/eligibility`
- **Timeout:** `10000` ms

Click **Register Contract**. The `sync_responder_url` is stored locally on Node B only — it is **never sent to participants** during the invite flow.

**JSON Schema Definition:**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["customer_id", "mobile", "product"],
  "properties": {
    "customer_id": { "type": "string", "x-pii": true },
    "mobile":      { "type": "string", "x-pii": true },
    "product":     { "type": "string", "enum": ["loan", "credit_card", "insurance"] },
    "pincode":     { "type": "string" }
  }
}
```

In Step 3, assign PII rules for `customer_id` and `mobile`.

### 11.3 Invite Node A

Node B → Data Contracts → `Loan Eligibility Check` → **Invite** → select **Node A** → **Send Invitations**.

### 11.4 Accept on Node A

Node A → Data Contracts → `Loan Eligibility Check` (status: Invited) → **Accept**.

### 11.5 Execute a Sync Request from Node A

**Via the UI:** Node A → **Transfer Logs → Initiate Transfer** → select `Loan Eligibility Check [SYNC]` → enter payload → **Send Request**.

Sample payload:

```json
{ "customer_id": "C-001", "mobile": "9876543210", "product": "loan" }
```

The governed response appears inline in the modal on success.

**Via the Client API:**

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

Expected: `{ "success": true, "response_payload": { "result": "ok" }, "duration_ms": 42 }`

### 11.6 Verify

| Check | Where |
|---|---|
| Sync audit row (caller) | Node A → Transfer Logs → Sync Calls tab |
| Sync audit row (receiver) | Node B → Transfer Logs → Sync Calls tab |
| Sync Calls (24h) counter | Dashboard stat card |
| `interaction_type: sync` badge | Data Contracts list |
| Participants column | Node B → Data Contracts — shows Node A as Active |
| Contract Inspector | Participants section shows Node A with status Active |

---

## 12. Advanced Tests

### Multi-Participant

Works identically for async and sync contracts. After Node A is Active:

1. Node B → invite **Node C** on the same contract
2. Node C → accept
3. Node C → Initiate Transfer using the same contract

Verify that audit logs on Node B attribute each transfer to its correct sender.

### Authorisation Rejection

Attempt a direct P2P call from a node that has not been invited:

```bash
curl -s -X POST http://localhost:8083/api/admin/transfers \
  -H "Content-Type: application/json" \
  -H "X-DX-P2P-HANDSHAKE: DX-P2P-PROTOCOL-V1" \
  -d '{
    "_func": "receive_transfer_stream",
    "contract_id": "<uuid-of-contract>",
    "sender_node_id": "UNINVITED-NODE",
    "transfer_id": "00000000-0000-0000-0000-000000000000",
    "file_name": "test.json",
    "file_data": "e30=",
    "sequence_number": 1,
    "message_timestamp": "2026-01-01 00:00:00.0"
  }'
```

Expected: HTTP 403 `Sender is not an authorised participant of this contract.`  
An audit entry `SECURITY_UNAUTHORIZED_TRANSFER` (CRITICAL) is written on Node B.

### Replay Protection — Async (Sequence Number)

Reset Node B's transfer history for Node A, then re-send the same file:

```bash
docker exec -i node-b-database-1 psql -U tsi_admin -d tsi_dx_node -c \
  "DELETE FROM data_transfers WHERE sender_node_id = 'NODE-A-SOUTH';"
```

A second transfer with a non-monotonic sequence number must be rejected with HTTP 403.

### Replay Protection — Sync (Nonce)

Send the same `idempotency_key` twice within the nonce TTL window — the second call must be rejected. After the TTL expires (~30 s), a call with a fresh nonce succeeds.

### Circuit Breaker (Sync Only)

Stop the mock responder on Node B, then send 6 consecutive sync calls from Node A. The 6th call should fail immediately (circuit open) without waiting for the full timeout.

```bash
docker compose -p node-b stop mock-responder
# ... send 6 requests from Node A ...
docker compose -p node-b start mock-responder
# Verify calls resume
```

---

## 13. Async vs Sync Comparison

| | Async | Sync |
|---|---|---|
| Who creates the contract | Receiver | Receiver |
| Who can initiate | Active participants | Active participants |
| Transfer payload | File (JSON or CSV) | JSON object |
| Response | None (queued, polled) | Inline HTTP 200 |
| Governance on send | L1 schema + L2 PII | L1 schema + L2 PII |
| Governance on receive | — | L2 PII only (response schema differs) |
| Audit table | `data_transfers` | `sync_audit_log` |
| Replay protection | Sequence number monotonicity | Nonce TTL (`sync_nonces` table) |
| Circuit breaker | None | Opens after 5 consecutive failures |
| Responder config | None needed | `sync_responder_url` in contract metadata (receiver-only) |

---

## 14. Teardown

**Stop Node A** (`-v` wipes the database volume):

```bash
docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-a down -v
```

**Stop Node B:**

```bash
docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-b down -v
```

**Remove shared network** (only when fully done with P2P testing):

```bash
docker network rm tsi-p2p-net
```

> **Note:** Omit `-v` to preserve database state between sessions. Add `-v` only when you need a clean slate (e.g. re-running DB init scripts).

---

## 15. Troubleshooting

**Server and database logs — Node A**

```bash
docker compose -p node-a logs -f server
docker compose -p node-a logs -f database
```

**Server and database logs — Node B**

```bash
docker compose -p node-b logs -f server
docker compose -p node-b logs -f database
```
