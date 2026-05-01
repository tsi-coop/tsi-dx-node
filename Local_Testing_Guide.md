# Local P2P Testing Guide

This guide walks through running two fully independent TSI DX Node instances (Node A and Node B) on a single development machine. The base `docker-compose.yml` used in production is extended by a `docker-compose.p2p.yml` overlay — no production files are modified.

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

Initialize the identity for each node via the web UI. Use the Docker service hostname as the FQDN and **always use port `8443`** - that is the internal Jetty HTTPS port that all P2P traffic uses, regardless of what host port the node is exposed on.

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

## 8. Contract Definition

**On Node A** (`http://localhost:8082`):

1. Go to **Data Contracts → New Contract**.
2. Select `NODE-B-NORTH` as the partner.
3. Define L2 Anonymization rules (e.g. Hash email, Mask phone).
4. Click **Register**, then **Propose**.

**On Node B** (`http://localhost:8083`):

1. Go to **Data Contracts**.
2. Locate the incoming proposal from `NODE-A-SOUTH`.
3. Click **Accept**. Both nodes should now show the contract as `Active`.

---

## 9. Transfer Service

**On Node A** (`http://localhost:8082`):

1. Go to **Transfer Logs → Initiate Transfer**.
2. Upload a sample lead file and start the transfer.

**Verification:**

| Check | Expected Result |
|---|---|
| Node A Mirror | File visible with source-side anonymization applied |
| Node B Received | Received file is bit-perfect to Node A's mirror |

---

## 10. Teardown

**Stop Node A** (-v wipes database volume)

```bash
docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-a down -v
```

**Stop Node B**

```bash
docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-b down -v
```

**Remove shared network** (only when fully done with P2P testing)
```bash
docker network rm tsi-p2p-net
```

> **Note:** Omit `-v` to preserve database state between sessions. Add `-v` only when you need a clean slate (e.g. re-running DB init scripts).

---

## 11. Troubleshooting

**Check server and database logs - Node A**

```bash
docker compose -p node-a logs -f server
```

```bash
docker compose -p node-a logs -f database
```

**Check server and database logs - Node B**

```bash
docker compose -p node-b logs -f server
```

```bash
docker compose -p node-b logs -f database
```
