# Example scripts

Shell scripts that drive two TSI DX Node instances through the whole exchange using only the public HTTP API: node setup, identity and partner handshake, data contract definition, an asynchronous transfer and a synchronous call. They are the scriptable equivalent of [Local Testing Guide](../../docs/guides/local-testing-guide.md) sections 5-11, and double as a worked reference for integrating against the API.

Concepts behind each step: [Architecture](../../docs/design/architecture.md), [Asynchronous Integration Guide](../../docs/guides/asynchronous-integration-guide.md), [Synchronous Integration Guide](../../docs/guides/synchronous-integration-guide.md).

## Prerequisites

- `curl`, `jq`, `openssl`, `base64`
- **Two running nodes** (see "Start Node A and Node B" below). The scripts only talk to the nodes' HTTP APIs; they do not start them. If a node is down, `01-node-setup.sh` fails with `Cannot reach http://localhost:8082/... - is the node running?`
- Fresh databases, or nodes you are happy to add example data to. The scripts are re-runnable, but they create contracts, applications and API keys.

## Start Node A and Node B

**Run these from the repository root**, not from `examples/scripts` (the compose and `.env.node-*` files live there). Node A listens on `localhost:8082`, Node B on `localhost:8083`; they reach each other as `node-a-server-1` / `node-b-server-1` over the shared `tsi-p2p-net` network. The compose file also starts the mock responder the sync step uses.

```bash
cd "$(git rev-parse --show-toplevel)"   # repository root, if you are in examples/scripts

docker network create tsi-p2p-net      # once; ignore "already exists"

docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-a --env-file .env.node-a up --build -d

docker compose -f docker-compose.yml -f docker-compose.p2p.yml \
  --project-name node-b --env-file .env.node-b up --build -d
```

Check both are up before running any script (the first build takes a few minutes):

```bash
docker ps --filter name=node- --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s -o /dev/null -w 'node-a: %{http_code}\n' http://localhost:8082/index.html
curl -s -o /dev/null -w 'node-b: %{http_code}\n' http://localhost:8083/index.html
```

Both `curl` lines should print `200`. Then:

```bash
cd examples/scripts
./run-all.sh
```

**Always pass `--project-name` and `--env-file`.** A plain `docker compose up` in the repository root uses the default project name `tsi-dx-node` and the default ports, which collide with the node-a stack (`Bind for :::5434 failed: port is already allocated`). If you did that, clean up with `docker compose -p tsi-dx-node down`.

To stop or remove the nodes and the example data, see [Teardown](#teardown).

## The scripts

| Script | What it does | API calls |
|---|---|---|
| [`01-node-setup.sh`](01-node-setup.sh) | Initialise each node: node identity + first administrator | `registeradmin`, `login`, `get_node_config` |
| [`02-identity-and-partners.sh`](02-identity-and-partners.sh) | Generate certificates, activate them, register each node as the other's partner, run the handshake | `import_node_certificate`, `create_partner`, `accept_partnership`, `list_partners` |
| [`03-define-contract.sh`](03-define-contract.sh) | Receiver authors an async and a sync contract, invites the sender, sender accepts | `create_contract`, `invite_node`, `accept_contract`, `get_contract`, `list_contracts` |
| [`04-async-transfer.sh`](04-async-transfer.sh) | Send a governed package, track it to `Delivered`, show what the receiver stored | `create_app`, `generate_api_key`, client `initiate_transfer`, `get_transfer_status`, `list_transfers`, `get_transfer_payload` |
| [`05-sync-call.sh`](05-sync-call.sh) | Real-time request/response through the responder; shows the audit row on both nodes. `--invalid` demonstrates L1 rejection | client `execute_sync_request`, `list_sync_audit_logs` |
| [`06-negative-tests.sh`](06-negative-tests.sh) | Things that must be refused, for both lanes: bad input, missing authority, unsafe file names, replays, responder failures, contract lifecycle, node security. Asserts the expected status for each and exits non-zero on any surprise. **[Full test case list](#negative-test-scenarios-06-negative-testssh)** | client API, plus partner-endpoint calls as a peer node would make them |
| [`run-all.sh`](run-all.sh) | Runs 01-06 in order and stops at the first failure | |


## Roles

The scripts follow the receiver-authority model: **Node B is the receiver** - it authors the contracts and hosts the sync responder. **Node A is the sender / caller** - it is invited, accepts, and its application pushes data or calls the service. Data flows A → B.

## Running one step at a time

Each script is standalone and reads what earlier steps recorded in the state directory.

```bash
./01-node-setup.sh                 # or: ./01-node-setup.sh a
./02-identity-and-partners.sh
./03-define-contract.sh            # or: async | sync
./04-async-transfer.sh [file.json] # default payloads/async-sample.json; run again to send more
./05-sync-call.sh [file.json]      # default payloads/sync-sample.json
./05-sync-call.sh --invalid        # expect HTTP 400 from the contract schema
./06-negative-tests.sh             # add --circuit-breaker to also trip the breaker (~70 s more)
```

## Configuration

Environment variables, with defaults that match the Local Testing Guide (full list in [`lib/common.sh`](lib/common.sh)):

| Variable | Default | Meaning |
|---|---|---|
| `NODE_A_URL`, `NODE_B_URL` | `http://localhost:8082`, `:8083` | Browser/API endpoint of each node |
| `NODE_A_ID`, `NODE_B_ID` | `NODE-A-SOUTH`, `NODE-B-NORTH` | Immutable node IDs |
| `NODE_A_HOST`, `NODE_B_HOST` | `node-a-server-1`, `node-b-server-1` | Name each node advertises to its partner; must resolve from the other container and be covered by the transport certificate |
| `P2P_PORT` | `8443` | Container-side HTTPS port used between nodes (not the host-mapped one) |
| `SETUP_TOKEN_A`, `SETUP_TOKEN_B` | `dev-node-a-setup-token`, `dev-node-b-setup-token` | Must equal each node's `TSI_DX_NODE_BOOTSTRAP_TOKEN` |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | `admin@example.org`, `Passw0rd!x` | First administrator on both nodes |
| `SYNC_RESPONDER_URL` | `http://mock-responder:8099/eligibility` | Where Node B forwards sync requests |
| `SYNC_TIMEOUT_MS` | `10000` | Sync call time budget |
| `DX_STATE_DIR` | `examples/scripts/.state` | Generated keys, certificates, IDs and API keys |
| `WAIT_SECS` | `60` | How long polling steps wait |

Example against nodes on other ports:

```bash
NODE_A_URL=http://localhost:18082 NODE_B_URL=http://localhost:18083 ./run-all.sh
```

## What each step shows

1. **Setup** - `registeradmin` is refused without the node's setup token, answers `409` once initialised, and a login proves the credentials.
2. **Identity and handshake** - after `accept_partnership` both partner records are `Active`; the handshake carries each node's public key over HTTPS.
3. **Contracts** - the receiver's contract is `Draft`, becomes `Active` on both nodes when the sender accepts, and lists the sender as an `Active` participant.
4. **Async** - the sender's copy is governed before dispatch; the receiver's stored payload shows `applicant_id` hashed and `mobile` masked, per the contract.
5. **Sync** - the response is returned inside the call with `duration_ms`; both nodes have an audit row whose request payload is already masked.
6. **Negative tests** - every refusal listed under [Negative test scenarios](#negative-test-scenarios-06-negative-testssh), with a pass/fail table at the end.

## Negative test scenarios (`06-negative-tests.sh`)

80 scenarios (77 by default, 3 more with `--circuit-breaker`). Each one sends something that must be refused (or a control that must still work) and checks the HTTP status and, where it matters, the error text. The run ends with a PASS/FAIL table and exits non-zero on any surprise.

How the script works:

- **Your example contracts are left alone.** It creates eight extra contracts (`Negative Test ... <timestamp>`) and two throw-away applications on every run, because some scenarios suspend a contract, purge a payload or point a contract at a broken responder.
- **Peer scenarios (*peer*)** call the receiver's own endpoint the way a partner node would: handshake header plus a signature made with Node A's identity key from `.state/`. They test the receiver's checks rather than what the sender would let through.
- **Slow case.** `--circuit-breaker` adds S20-S22 (about 70 s, because of the 60 s cooldown).
- **Timezone.** Replay checks write timestamps in `NODE_TZ` (default `Asia/Kolkata`, the image's `TZ`).

### Async lane

| ID | Scenario | Expected |
|---|---|---|
| A01 | `initiate_transfer` with no API key headers | `401` |
| A02 | Wrong API secret | `401` |
| A03 | Unknown API key | `401` |
| A04 | `file_data` is not valid Base64 | `400` |
| A05 | `file_data` is not valid JSON on a `format: json` contract (fail-fast) | `400` |
| A06 | `file_name` / `file_data` missing | `400` |
| A07 | Unknown function name | `400` |
| A08 | Contract id does not exist | `403` |
| A09 | Application not authorised for the contract | `403` |
| A10 | `get_transfer_status` for a transfer that is not yours | `403` |
| A10b | Async transfer on a **sync** contract | `403` |
| A11.1-5 | Unsafe `file_name` on the sender API: `../../../../tmp/dx-pwned`, `/etc/dx-pwned`, `sub/dir.json`, `..\evil.json`, `..` | `400` |
| A12 | Control: a plain `file_name` is still accepted | `201` |
| A13a/b | Payload that breaks the contract schema: accepted for processing, then the transfer ends `Failed` with a validation error before it leaves the node | `201`, then `Failed` |
| A14 | Contract suspended by the receiver, then a transfer is initiated | `403` |
| A15 | Six transfers started at the same moment on one contract all arrive (sequence numbers never collide) | all `Delivered` |
| A16a/b | Contract with `retention_policy_days: 0`: after a maintenance run the stored payload is deleted and the transfer is marked purged | payload present, then gone |

### Receiver peer endpoint, async (*peer*)

| ID | Scenario | Expected |
|---|---|---|
| R01 | `file_name` with `../` segments | `400` |
| R02 | Body names a sender that is not a participant of the contract | `401` |
| R03 | Message timestamp outside the 5-minute window (stale replay) | `403` |
| R04 | Sequence number not greater than the last received (replay) | `403` |
| R05 | The same call without the handshake header | `401` |
| V01 | Payload breaks the receiver's own schema (a sender skipped L1) | `400` |
| V02 | PII sent in clear: `applicant_id` not hashed, `mobile` not masked (a sender skipped L2) | `400` |
| V03 | Contract is a sync contract, not async | `403` |
| V04 | Contract does not exist on the receiver | `403` |
| V05 | Control: a correctly governed payload is accepted | `200` |
| V06 | The same transfer delivered again after a lost answer: acknowledged, not stored twice | `200` `duplicate` |

### Peer authentication (*peer*)

| ID | Scenario | Expected |
|---|---|---|
| P01 | Handshake header but no signature | `401` |
| P02 | Signed with a key that is not Node A's | `401` |
| P03 | Signature timestamp 10 minutes old | `401` |
| P04 | The same request id used twice (a captured request replayed) | `401` |
| P05 | Request addressed to a different node | `401` |
| P06 | A node signing as a partner it is not (identity not registered / wrong key) | `401` |
| P07 | Body names a different sender than the signer | `401` |
| P08 | `probe`, the bootstrap call, may be unsigned | `200` |

### Sync lane

| ID | Scenario | Expected |
|---|---|---|
| S01 | Wrong API secret | `401` |
| S02 | Request breaks the contract schema (L1): required fields missing | `400` |
| S03 | Wrong field type (`mobile` sent as a number) | `400` |
| S04 | `request_payload` missing | `400` |
| S05 | `contract_id` missing | `400` |
| S06 | Contract id does not exist | `403` |
| S07 | Contract is async, not sync | `403` |
| S08 | Application not authorised for the contract | `403` |
| S09 | Control: a valid call still succeeds | `200` |
| S10 | Responder refuses the connection | `5xx` |
| S11 | Responder does not answer within `sync_timeout_ms` (2 s) | `5xx` |
| S12 | The failed call appears in the caller's `sync_audit_log` as `ERROR` / `TIMEOUT` | present |
| S13 | A healthy contract still works after two failures (a success resets the breaker) | `200` |
| S14 | Contract suspended by the receiver, then a call is made | `403` |
| S15a | First call with a new `idempotency_key` runs | `200` |
| S15b | Same key, same request: the recorded answer is returned and the partner is not called again | `200` `idempotent_replay` |
| S15c | Same key, different request | `400` |
| S15d | The partner executed it once (one audit row on the receiver) | 1 row |
| S16a/b | Contract with a `HASH` rule on `customer_id`: the receiver saw the SHA-256 of the value exactly once, not a hash of a hash | hash of `C-001` |
| S20-22 | `--circuit-breaker` only: after 5 consecutive failures the 6th call fails fast with *circuit open*; the healthy contract to the same partner is refused too (the breaker is per partner); after the 60 s cooldown a healthy call closes it | `5xx`, `5xx`, `200` |

### Receiver peer endpoint, sync (*peer*)

| ID | Scenario | Expected |
|---|---|---|
| R10 | First use of a nonce | `200` |
| R11 | The same nonce again (replay) | `403` |
| R12 | Nonce missing | `400` |
| R13 | The same call without the handshake header | `401` |
| R14 | Handshake header but no signature | `401` |
| R15 | Request breaks the receiver's schema | `400` |
| R16 | `mobile` sent in clear: the caller skipped the mask | `400` |

### Node security

| ID | Scenario | Expected |
|---|---|---|
| N01 | Console page (`dashboard.html`) without a session | `302` to login |
| N02 | `index.html` (login) stays public | `200` |
| N03 | Admin API without a JWT | `401` |
| N04 | Peer handshake header on an admin function (`list_contracts`) | `401` |
| N05 | Malformed JWT | `401` |
| N06 | `registeradmin` with a wrong setup token | `401` |
| N07 | Login with a wrong password | `401` |
| N08 | Admin token forged with the old built-in signing key | `401` |

### Not automated

These need a container to be stopped or the node to be started with a different environment, so the script leaves them to you.

| Scenario | How to check by hand | Expected |
|---|---|---|
| Receiver offline during an async transfer | `docker stop node-b-server-1`, run `./04-async-transfer.sh` or `initiate_transfer`, watch `get_transfer_status`, then `docker start node-b-server-1` | `Pending` with *attempt 1 of 5, retrying in 30s*, then `Delivered`; one `Received` row on Node B |
| Receiver offline for longer than the retry budget (about 40 min) | as above, leave it stopped | `Failed` after 5 attempts |
| Node started without a JWT secret in production mode | start a node with `TSI_DX_NODE_ENV=production` and no `TSI_DX_NODE_JWT_SECRET` | the application refuses to start |
| Nonce clean-up | `run_maintenance` reports `nonces_removed` once rows are 24 h past expiry | rows removed |
| Sync responder container stopped | `docker stop node-b-mock-responder-1`, run `./05-sync-call.sh` | `5xx` (S10 covers the same path with an unreachable address) |
| Certificate or hostname mismatch | use a hostname outside the transport certificate's SANs | `Trust Denied` at the handshake |

### Remaining limits (not asserted)

- The Jetty connector does not require client certificates. Peers are authenticated by the message signature, which holds behind a TLS-terminating proxy; still keep the P2P port reachable only from partners.
- `probe` and `receive_partnership_proposal` are accepted unsigned because the sender is not yet a known partner; they only create `Pending` records an administrator has to accept.
- Node identity private keys are stored in the node database as PEM text. Protect the database and its backups accordingly.
- Sequence ordering, the circuit breaker and the replay cache are per node process; run one node process per database.
- A purged payload is deleted from the storage path; copies in backups of that volume are outside the node's control.

## Teardown

Run from the repository root. Pick the level you need.

**1. Stop the nodes, keep everything.** Containers are removed, databases and `.state/` are kept, so `up -d` brings the same nodes back and the scripts carry on where they were.

```bash
docker compose -p node-a down
docker compose -p node-b down
```

**2. Remove the nodes and all example data.** `-v` deletes each node's database volume: the node identity, administrator, partners, contracts, transfers, applications and API keys are gone. Because the keys and IDs in `.state/` then no longer match anything, delete it too, otherwise the next run tries to reuse them.

```bash
docker compose -p node-a down -v
docker compose -p node-b down -v
rm -rf examples/scripts/.state
```

Transferred payload files live in the node's storage volume (`TSI_EXPORT_PATH`) and are removed by the same `-v`.

**3. Remove everything the example created on the machine.**

```bash
docker network rm tsi-p2p-net                       # shared peer network; only if no other stack uses it
docker rmi tsicoop/tsi-dx-node:latest               # image built by `up --build`
docker compose -p tsi-dx-node down -v               # only if you once ran a plain `docker compose up`
```

Check what is left with `docker ps -a --filter name=node-` and `docker volume ls | grep node-`.

**Start over without removing the nodes.** If you only want the scripts to begin from scratch against nodes you keep, delete just the state and use fresh nodes (level 2) for a clean run; with existing nodes, `01-node-setup.sh` answers `409` (already initialised), and step 02 re-issues certificates and re-runs the handshake. `06-negative-tests.sh` adds extra `Negative Test ...` contracts and applications on every run; level 2 is the way to clear them.

**Changed ports or project names?** Use the same `--project-name` you started with, plus the same `-f` / `--env-file` flags if the compose files declare ports differently:

```bash
docker compose -f docker-compose.yml -f docker-compose.p2p.yml --project-name node-a --env-file .env.node-a down -v
```

## Notes

- **State and secrets.** `.state/` (git-ignored) holds private keys and API secrets in plain files. This is for evaluation only; delete the directory to start over. Rotating `.state` while keeping the nodes is fine - step 2 re-issues certificates and re-runs the handshake.
- **Certificates.** The scripts create self-signed certificates with the node hostname as CN. Use your own CA in real deployments.
- **Hostnames.** The development transport keystore only covers `node-a-server-1`, `node-b-server-1` and `localhost`. Using other hostnames makes the handshake fail with `Trust Denied`; regenerate the keystore SANs if you change them.
- **Real responders.** To see a real answer in step 5, run an HTTP service that accepts a JSON `POST` and returns a JSON object, reachable from Node B, and pass its URL as `SYNC_RESPONDER_URL` before step 3. Contracts are found by name, so remove the existing sync contract (or use fresh nodes) for the new URL to take effect.
