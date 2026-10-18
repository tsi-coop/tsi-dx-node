# TSI DX Node: Architecture

How TSI DX Node is built and why. This is the single design reference; how-to material (setup, API calls, deployment, testing) lives in [guides](../guides/).

| Section | Covers |
|---|---|
| [1. Purpose and principles](#1-purpose-and-principles) | What the node is for, the rules the design follows |
| [2. System overview](#2-system-overview) | Components, ports, deployment unit |
| [3. Trust and security model](#3-trust-and-security-model) | Identities, partner trust, peer signatures, who can call what |
| [4. Contract model](#4-contract-model) | Receiver-authored contracts, participants, lifecycle |
| [5. Governance](#5-governance) | L1 validation, L2 anonymisation, enforcement on both nodes |
| [6. Asynchronous lane](#6-asynchronous-lane) | Staged, sequenced, retried package delivery |
| [7. Synchronous lane](#7-synchronous-lane) | Real-time governed request/response |
| [8. Choosing a lane](#8-choosing-a-lane) | Side-by-side comparison |
| [9. Data model](#9-data-model) | Tables and what each holds |
| [10. Audit and evidence](#10-audit-and-evidence) | What is recorded and where |
| [11. Operations](#11-operations) | Background jobs, retention, configuration |
| [12. Design decisions](#12-design-decisions) | Why it is shaped this way, and how it got here |
| [13. Limits and known gaps](#13-limits-and-known-gaps) | Stated plainly |
| [14. Code map](#14-code-map) | Where each concern lives |
| [15. Consent channel (CEF-EVENTS)](#15-consent-channel-cef-events) | Consent, consent changes and erasure between nodes, separate from data |

---

## 1. Purpose and principles

TSI DX Node is an open-source node for **peer-to-peer, governed data exchange between independent organisations**. Each organisation runs its own node. Nodes exchange data directly, with no central intermediary, under a data contract that both sides can inspect and that the node enforces.

Principles the rest of the design follows:

1. **The receiver is the contract authority.** The node that owns the destination or the service defines the contract (schema, anonymisation rules, who may take part). Senders and callers are invited participants and do not author terms.
2. **Governance on the wire, not in application code.** Structure (L1) and PII handling (L2) are enforced by the nodes on every exchange, on both ends. A node never takes the other side's word that data was governed.
3. **Every peer is authenticated per message.** A request between nodes is signed with the sender's identity key and checked against the key registered for that partner.
4. **Two lanes, one foundation.** Batch (async) and real-time (sync) exchange share partners, contracts, governance and audit; only delivery differs.
5. **Evidence on both nodes.** Each exchange leaves a record on the sender and on the receiver, in already-governed form.
6. **Sovereign by default.** Payloads and keys stay on the node's own infrastructure; the only thing that crosses to a partner is the governed payload.

## 2. System overview

```
        Client API                                   Admin console
  (applications push / call)                (contracts, partners, transfers, users)
  API key + secret, per-contract            JWT session cookie, role-based
              │                                          │
              ▼                                          ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │ SHARED FOUNDATION                                               │
   │  Partner registry + identity keys · Peer message signatures     │
   │  Receiver-authored contracts · L1 validation · L2 anonymisation │
   │  Audit log                                                      │
   └─────────────────────────────────────────────────────────────────┘
              │                                          │
              ▼                                          ▼
     Async delivery (TransferEngine)          Sync delivery (SyncEngine)
     stage · govern · sequence · send         govern · call · verify · return
     retry · mirror                           circuit breaker · idempotency
              │                                          │
              └──────────────► PostgreSQL ◄──────────────┘
                              storage volume (payload files)
```

| Aspect | Detail |
|---|---|
| Runtime | Java 17 servlet application (Jetty), one WAR, packaged as a container image |
| Database | PostgreSQL; schema in `db/` (`01_init.sql` onward), applied on first start |
| Ports | HTTP `8080` (console and Client API), HTTPS `8443` (node-to-node) |
| Storage | `TSI_EXPORT_PATH` (active storage path) for staged and received payload files; use a persistent volume |
| Entry points | `/api/client/dx` (applications), `/api/admin/*` (console and peer functions) |
| Deployment unit | One node process per database. Ordering, the circuit breaker and the request-id cache are per process |

## 3. Trust and security model

### 3.1 Identities

- **Node identity.** Each node has a node id, a public FQDN and an identity key pair with a certificate, generated and activated through the console. The private key never leaves the node.
- **Partner registry.** A node trusts another node only after the partner is registered with its public key and a handshake has completed. Only registered partners can be invited to contracts.
- **Applications.** Systems on the organisation's side authenticate to their own node with an API key and secret, scoped to the contracts bound to that application.
- **Administrators.** Console users authenticate with a password and receive a signed session token, held in an `HttpOnly`, `SameSite=Lax` cookie.

### 3.2 Peer authentication: signed messages

Every node-to-node request carries `X-DX-NODE-ID`, `X-DX-TARGET-NODE-ID`, `X-DX-TIMESTAMP`, `X-DX-REQUEST-ID` and `X-DX-SIGNATURE`. The signature (SHA-256 with RSA, or ECDSA for EC keys) covers, joined by newlines: `DX-P2P-SIG-V1`, sender id, target id, function, timestamp, request id, and the SHA-256 of the body.

The receiving node refuses with `401` when:

| Check | Why |
|---|---|
| Request is unsigned (except the two bootstrap functions) | Anything else could be anyone |
| Signer is not a registered partner, or the relationship is `Terminated`/`Inactive` | Trust is explicit |
| Signature does not verify against the registered key | Impersonation |
| Timestamp more than 5 minutes off | Stale or pre-built requests |
| Request id already seen | A captured request cannot be replayed |
| Target is another node | A request for one node cannot be redirected to another |
| `sender_node_id` in the body differs from the signer | A valid partner cannot speak as another |

`probe` and `receive_partnership_proposal` may arrive unsigned, because the sender is not yet a known partner; they only create `Pending` records that an administrator must accept. The header `X-DX-P2P-HANDSHAKE: DX-P2P-PROTOCOL-V1` is a fixed, public routing marker, not a credential: it only selects the peer-function allow-list below.

This is message-level authentication, so it holds behind a TLS-terminating proxy. The Jetty connector does not require client certificates.

### 3.3 Who can call what

The filter in front of every `/api/admin/*` route admits a request only through one of two paths:

- **Administrator**: a valid session token (header or cookie). Console pages are gated server-side by a filter that redirects to login without a session. Token verification happens before any body is parsed, so unauthenticated callers cannot probe request schemas.
- **Peer**: the handshake header, a function on the route's allow-list, and a valid signature.

| Route | Peer functions (anything else needs an administrator) |
|---|---|
| `/api/admin/partners` | `probe`, `receive_partnership_proposal`, `receive_termination_request`, `receive_termination_finalization` |
| `/api/admin/contracts` | `receive_contract_invitation`, `confirm_invitation`, `decline_invitation`, `notify_participant_suspended`, `notify_contract_suspended`, `receive_contract_update` |
| `/api/admin/transfers` | `receive_transfer_stream`, `receive_sync_request` |

Both the `X-DX-FUNCTION` header and the body `_func` must name an allowed function, because handlers differ in which they honour.

### 3.4 Other controls

| Control | Behaviour |
|---|---|
| First-time setup | `registeradmin` requires the setup token (`TSI_DX_NODE_BOOTSTRAP_TOKEN`), compared in constant time, before touching the database; check-and-insert is serialisable, so two racing setups cannot both win |
| Signing key | `TSI_DX_NODE_JWT_SECRET` (32+ chars) has no built-in default; production refuses to start without it, development uses a random per-process key |
| File names | `file_name` must be a single plain name; separators, `..`, `:`, NUL and control characters are rejected, and the resolved path must stay inside the storage directory. Applied on every write and every read of a stored file |
| Directory listings | Disabled |
| Responders | The node presents no credentials to `sync_responder_url`; secure it by network placement |

Deployment settings and the checklist are in the [Security Hardening Guide](../guides/security-hardening-guide.md).

## 4. Contract model

### 4.1 Who creates and who takes part

Only the **receiving node** creates a contract, always from its own point of view; there is no "outgoing" direction. A contract is not bilateral: Node B can define one contract and invite Node A, Node C and Node D under the same schema and rules.

```
data_contracts
  contract_id            PK
  name
  receiver_node_id       the creating node
  interaction_type       async | sync
  schema_definition      JSON Schema (draft-07), or a CSV field list
  metadata               format, governance_rules, sync_responder_url, sync_timeout_ms
  pii_fields             fields the contract treats as PII
  retention_policy_days  how long finished payloads are kept (NULL = keep)
  status                 Draft | Active | Suspended

contract_participants
  contract_id, node_id   PK → partners.node_id (invited sender)
  status                 Invited | Active | Rejected | Suspended
  invited_at
```

The authorised senders for a contract are its `contract_participants` rows with `status = Active`. The sender's copy of the contract is created by the invitation and carries everything it needs, except `sync_responder_url`, which is stripped because it is the receiver's internal address.

### 4.2 Lifecycle

```
Receiver creates contract (Draft)
   → invites one or more partners                  invite_node
   → invitation delivered over the peer channel    receive_contract_invitation
   → each partner accepts or rejects on its own    confirm_invitation / decline_invitation
   → accepted partners are Active participants
   → any Active participant may send or call
   → receiver may suspend one participant or the whole contract
                                                   notify_participant_suspended / notify_contract_suspended
```

Invitations are independent: Node C declining does not affect Node A, and further nodes can be invited at any time. Suspension is not reversible; a new contract is created instead.

### 4.3 Editing a contract

Only the receiving node can edit a contract, and only while it is `Draft` or `Active`.

| What | When it can change | Propagated to participants |
|---|---|---|
| Name, `retention_policy_days` | Draft or Active | Yes (`receive_contract_update`) |
| `sync_timeout_ms` (sync) | Draft or Active | Yes |
| `sync_responder_url` (sync) | Draft or Active | No: it is the receiver's internal address |
| `schema_definition`, anonymisation rules, `pii_fields` | Only while Draft and no partner has been invited | Not needed: frozen once invited |
| `interaction_type`, `format` | Never | n/a |

The terms are what participants agreed to, so they are frozen from the first invitation; changing them means a new contract. Peer notifications about a contract (`receive_contract_update`, `notify_*_suspended`) are accepted only from the node that owns it, and `confirm_invitation` / `decline_invitation` only from the invitee they name.

### 4.4 Authorisation

On the sender, the contract must be `Active`, of the right `interaction_type`, the local node an `Active` participant, and (for the Client API) the application bound to the contract. On the receiver the same is re-checked against its own copy: the contract must be Active, its `receiver_node_id` must be this node, the type must match the lane, and the signer must be an Active participant.

## 5. Governance

Two layers apply to every exchange, in both lanes.

| Layer | What it enforces | Contract fields |
|---|---|---|
| **L1: structure** | Payload validates against the contract schema (JSON Schema for `json`; exact header/field list for `csv`) | `schema_definition`, `metadata.format` |
| **L2: PII** | Named fields are anonymised: `MASK` (last four characters kept, `****1234`), `HASH` (SHA-256 hex), `TOKENIZE` (deterministic `[TOKEN:uuid]`), or `NONE` | `metadata.governance_rules.pii_anonymization` |

### 5.1 Both ends enforce, nothing is transformed twice

| Node | What it does |
|---|---|
| **Sender / caller** | Validates against the schema, then applies L2. This is data minimisation at source: raw PII does not leave the sender |
| **Receiver** | Validates the payload against **its own** copy of the contract (L1), and **verifies** every anonymised field is in its declared form (`MASK` matches `****xxxx`, `HASH` is 64 hex characters, `TOKENIZE` matches the token pattern). It does not transform the data again |

A payload that fails is refused with `400` and audited (`SECURITY_CONTRACT_VIOLATION` on the async lane), and nothing is stored or forwarded. Fields with an anonymisation rule are exempt from the schema's value rules (patterns, lengths) on the receiver, because by then they hold a mask, hash or token; they must still be present if the schema requires them.

For sync responses the roles reverse: the receiving node anonymises the responder's answer (it holds the data), and the calling node verifies it. Responses are not schema-validated, since a response has a different shape from a request; only the anonymisation rules apply.

## 6. Asynchronous lane

Moves a governed package from a sending node to a receiving node and tracks it to delivery. The sender does not wait for the receiver's business system; it hands the package to its own node.

### 6.1 Flow

```
 App / admin            Node A (sender)                         Node B (receiver)
      │ initiate_transfer     │                                         │
      ├──────────────────────▶│ contract Active, A an Active participant│
      │                       │ stage file; record transfer Pending     │
      │◀── transfer_id ───────┤                                         │
      │                       │ worker claims it: Processing            │
      │                       │ L1 validate + L2 anonymise (once)       │
      │                       │ lane lock: next sequence + timestamp    │
      │                       ├────────────────────────────────────────▶│ signature, participant
      │                       │   receive_transfer_stream (signed)      │ freshness, sequence
      │                       │                                         │ contract + L1 + L2 verify
      │                       │◀── 200 ─────────────────────────────────┤ store; status Received
      │                       │ status: Delivered                       │
```

1. **Initiate.** The request names a `contract_id`, a `file_name` and Base64 content. The receiver comes from the contract, never from the request. JSON contracts are parsed on arrival and refused with `400` if not JSON.
2. **Stage and register.** The file is written to the active storage path; a `data_transfers` row is created `Pending`; the `transfer_id` is returned immediately.
3. **Claim.** A worker (10 concurrent) claims the transfer with an atomic `Pending → Processing` update. A scheduler also sweeps for due `Pending` transfers every 30 seconds, so none is stranded by a restart and two workers never run the same transfer.
4. **Govern once.** L1 and L2 are applied and the governed bytes replace the staged file, so what the node retains is exactly what was sent. A marker on the row records that the file is governed, so a retry never transforms it again. A violation ends the transfer `Failed` with the reason; nothing is sent.
5. **Sequence and send.** Under a lock per `(contract, receiver)`, the next sequence number and a timestamp are allocated and the signed message is sent. The lock is held until the result is recorded, so numbers go out in order and cannot collide even when many transfers start at once.
6. **Receive.** The receiver verifies, in order: signature (§3.2); sender an Active participant; the transfer is not one it already holds (duplicates are acknowledged, not stored again); timestamp within 5 minutes; sequence greater than the last received from that sender on that contract; contract and payload (§5.1). Only then is the payload stored and the transfer recorded `Received`.
7. **Complete.** `2xx` marks the sender's transfer `Delivered`.

### 6.2 Status lifecycle

| Status | Where | Meaning |
|---|---|---|
| `Pending` | Sender | Staged and registered, waiting for a worker; also a transfer waiting for its next retry |
| `Processing` | Sender | Claimed; being governed and dispatched |
| `Delivered` | Sender | Receiver acknowledged with `2xx` |
| `Failed` | Sender | Governance violation, missing file, a `4xx` rejection from the peer, or retries exhausted; reason recorded |
| `Received` | Receiver | Verified and stored |

### 6.3 Replay protection

- **Freshness:** message timestamp within 5 minutes of the receiver's clock. Node clocks must be synchronised.
- **Monotonic sequence:** greater than the highest already received from that sender on that contract.
- **Idempotent delivery:** a transfer id the receiver already holds is acknowledged with `duplicate: true` and not stored again, so a retry after a lost answer is safe.
- **Peer signature:** timestamp window and single-use request id (§3.2) apply in addition.

Rejections return `403` (replay) or `401` (signature) and are audited at `CRITICAL` (`SECURITY_REPLAY_BLOCKED`, `SECURITY_UNAUTHORIZED_TRANSFER`).

### 6.4 Retry

Transport failures (peer unreachable, `5xx`, `408`, `429`) put the transfer back to `Pending` with a backoff of 30 s, 2 min, 8 min and 32 min; five attempts in total, then `Failed`. The error message records which attempt failed. Governance errors and `4xx` rejections are not retried. Each attempt takes a fresh sequence number (a failed attempt consumed none at the receiver).

### 6.5 Retention

Each contract carries `retention_policy_days`. A maintenance job (hourly by default) deletes the payload file of every finished transfer older than that, sets `retention_status = Purged` and `purged_at`, and keeps the metadata row. `NULL` keeps payloads indefinitely; `0` purges at the next run. Administrators can trigger it with `run_maintenance`.

### 6.6 Payload size

The whole package is held in memory and sent as one Base64 JSON message. Limits are the node's heap and the receiving node's request handling; split very large datasets into several packages.

## 7. Synchronous lane

A governed request/response call between two nodes, answered within a timeout. "Real-time" here means synchronous request/response; it is not streaming, pub/sub or webhook push.

### 7.1 Flow

```
 Caller app     Node A                          Node B                         Responder service
     │ execute_sync_request                        │                                  │
     ├────────▶│ app authorised? contract Active   │                                  │
     │         │ and sync? L1 + L2 govern request  │                                  │
     │         │ idempotency key already done?     │                                  │
     │         │ circuit breaker closed? nonce     │                                  │
     │         ├──────────────────────────────────▶│ signature, participant           │
     │         │   receive_sync_request (signed)   │ claim nonce                      │
     │         │                                   │ L1 + L2 verify request           │
     │         │                                   ├─────────────────────────────────▶│
     │         │                                   │◀─────────────────────────────────┤
     │         │                                   │ L2 anonymise response; audit     │
     │         │◀──────────────────────────────────┤                                  │
     │◀────────┤ L2 verify response; audit         │                                  │
```

### 7.2 Behaviour

- **The receiver owns the service.** The contract carries the responder URL and the timeout; the caller never learns the URL.
- **Responder contract.** One `POST` with `Content-Type: application/json` and the governed request as body. It must return `2xx` and a JSON object within `sync_timeout_ms` (default 10 000 ms). Non-2xx becomes `502`, no answer in time `504`.
- **Replay protection:** a fresh nonce per call, claimed by a unique insert on the receiver; a repeat is `403`. Nonces are kept 24 hours past expiry; the signature's 5-minute window covers anything older.
- **Idempotency:** a call with an `idempotency_key` that already succeeded in the last 24 hours returns the recorded response with `idempotent_replay: true` and does not call the partner. The same key with a different request is `400`. Only `SUCCESS` is replayed; a failed call with the same key runs again.
- **Circuit breaker:** per partner, in memory on the calling node. After 5 consecutive failures calls fail immediately; after 60 s one attempt is let through and a success closes it. It is per partner, not per contract.
- **Connection reuse:** the calling node keeps one pooled HTTP client per partner.

### 7.3 Errors seen by the caller

| Situation | Result |
|---|---|
| Missing or invalid API key / secret | `401` |
| App not bound, contract not Active, or not `sync` | `403` |
| `contract_id` or `request_payload` missing | `400` |
| Request fails the schema | `400`, `Contract Violation: ...` |
| Same `idempotency_key`, different request | `400` |
| Circuit open | error, immediately, no network call |
| Partner unreachable, rejected the call, timed out, or answered in violation of the contract | error; audited and counted toward the breaker |

## 8. Choosing a lane

| | Asynchronous | Synchronous |
|---|---|---|
| Caller waits | No: tracked by `transfer_id` | Yes: response in the same call |
| Payload | File or JSON document, any size the node can stage | Small JSON request and response |
| Governance applied | Sender, before dispatch; verified by receiver | Caller on request, receiver on response; each verified by the other |
| Replay protection | Sequence number + freshness window | Single-use nonce |
| Duplicate protection | Transfer id | Idempotency key |
| Failure handling | Retried, then `Failed` with reason | Immediate error; circuit breaker |
| Evidence | `data_transfers` + payload on both nodes | `sync_audit_log` on both nodes |
| Use for | Loan files, repayments, reconciliations, bulk PII | Eligibility, KYC validation, OTP, balance, decision |

Keep large or PII-heavy data on the async lane. Use sync only where something is waiting on the answer.

## 9. Data model

| Table | Holds |
|---|---|
| `node_config` | This node's id, FQDN, port, storage paths |
| `node_certificates` | Identity key pair and certificate (one active) |
| `partners` | Registered partner nodes: id, FQDN, public key, status |
| `data_contracts` | Contracts (§4.1), including `interaction_type`, `metadata`, `retention_policy_days` |
| `contract_participants` | Invited / active / rejected / suspended senders per contract |
| `app_contracts`, apps, API keys | Which application may use which contract, and its credentials |
| `data_transfers` | One row per async transfer: parties, file, size, checksum marker, sequence, timestamps, status, error, `retry_count`, `next_retry_at`, `retention_status`, `purged_at` |
| `sync_nonces` | Nonces claimed on the receiver; `expires_at` |
| `sync_audit_log` | One row per sync call on each node, post-anonymisation |
| `audit_logs` | Administrative and protocol events (logins, contract changes, rejections, payload inspection) |
| `users` and roles | Console users |

The built-in `CEF-EVENTS` contracts (§15) are ordinary rows in `data_contracts` and `contract_participants`; no table was added for them.

`retry_count` and `next_retry_at` are added by `db/05_transfer_retry.sql`, and also applied by the node at start-up, so existing databases need no manual step.

## 10. Audit and evidence

| Evidence | Async | Sync |
|---|---|---|
| Per-exchange record | `data_transfers` row on both nodes | `sync_audit_log` row on both nodes |
| Payload | Governed copy on the sender, received copy on the receiver (comparable) | Request and response, post-anonymisation, in the log row |
| Rejections | `audit_logs`: replay, unauthorised sender, contract violation | `sync_audit_log` `ERROR`/`TIMEOUT` rows; replay recorded |
| Payload inspection | `DATA_ACCESS` audit event | n/a (payload is in the log) |

Payloads are stored post-anonymisation; the logs never hold the raw PII a contract masks. Purged payloads leave the metadata row as evidence that the exchange happened.

## 11. Operations

| Job | Schedule | Does |
|---|---|---|
| Pending sweep | every 30 s | Starts due `Pending` transfers (new and retrying) |
| Maintenance | `TSI_DX_NODE_MAINTENANCE_SECONDS`, default 3600 | Retention purge; removes sync nonces 24 h past expiry |

| Setting | Purpose |
|---|---|
| `TSI_DX_NODE_BOOTSTRAP_TOKEN` | Authorises first-time setup |
| `TSI_DX_NODE_JWT_SECRET` | Session signing key |
| `TSI_DX_NODE_ENV` | `local`/`development`/`dev` relax cookie `Secure` and the JWT requirement |
| `TSI_DX_NODE_P2P_SIGNATURES` | `optional` accepts unsigned peer calls, for rolling upgrades only |
| `TSI_DX_NODE_MAINTENANCE_SECONDS` | Maintenance interval |
| `TSI_EXPORT_PATH` | Active storage path |

Full checklist: [Security Hardening Guide](../guides/security-hardening-guide.md).

## 12. Design decisions

**Receiver-authored, multi-participant contracts.** The first model was bilateral: a contract named one sender and one receiver partner and had a direction. That did not match practice (a warehouse or API provider defines what it accepts) and forced duplicate contracts per consumer. The model became a single receiver-owned contract with a participants table. Existing bilateral contracts were migrated by promoting the sender to a participant (`db/03_contract_participants.sql`, `db/04_suspended_participant_status.sql`). The UI lost the Direction field and gained an invite flow and an *Invited Nodes* column; initiation for senders is unchanged and lists only contracts where the local node is an Active participant.

**Sync lane added without touching async.** Real-time calls (eligibility, OTP, decisioning, balance) were riding bespoke APIs outside governance. Rather than bend the batch pipeline, a second delivery engine was added behind the same contract and governance core, selected per contract by `interaction_type` (default `async`, so existing contracts did not change). Reused unchanged: partner registry, identity and PKI utilities, schema validation, audit. New: `SyncEngine`, the nonce and audit tables, client function `execute_sync_request`, per-partner client pooling. Guardrails that still hold: async is not modified by sync; sync is opt-in per contract; PII-heavy bulk stays on async; every sync call is audited on both sides; anonymisation on sync is a conscious latency trade-off. UI additions were an interaction-type choice in the contract wizard, an *Interaction* badge, a *Sync Calls* tab, a *Sync Calls (24h)* dashboard card and a Sync Request audit filter.

**Per-message signatures instead of a shared header.** The first peer channel trusted a fixed header value. That value is public, so it authenticated nothing. It was first restricted to an allow-list of peer functions, then replaced as the authenticator by signatures made with identity keys the nodes already had, which needs no connector configuration and survives TLS termination in front of the node.

**Receiver verifies, never re-transforms.** Applying governance on both ends would hash identifiers twice and still leave the receiver trusting the sender's claim. The receiver instead validates against its own contract and checks the anonymised form, which makes it the authority without altering data.

**Serialised sends per contract.** Sequence numbers must arrive in order for the monotonic check to hold. Allocating and consuming them under one lock per `(contract, receiver)` keeps ordering without a global lock; the cost is that one slow peer delays only its own contract.

**Compliance rationale.** Because L1 and L2 apply to request and response alike, real-time calls inherit field-level anonymisation enforced on the wire rather than hoped for in application code, a Contract Inspector view of exactly which fields are governed on a link, and an immutable per-call evidence trail. The original design note framed this against India's DPDP Rules (notified November 2025, substantive provisions effective mid-May 2027).

## 13. Limits and known gaps

| Area | Limit |
|---|---|
| Transport | The Jetty connector does not require client certificates; peers are authenticated by message signature. Restrict the P2P port to partners anyway |
| Bootstrap | `probe` and `receive_partnership_proposal` are accepted unsigned; they only create `Pending` records |
| Key storage | Identity private keys are stored in the database as PEM text. Protect the database and its backups |
| Scale-out | Sequence ordering, the circuit breaker and the request-id cache are per process; run one node process per database |
| Streaming | No streaming, pub/sub or push; use async and have the receiving system collect |
| Sync payloads | JSON objects only; responder authentication is by network placement |
| Idempotency | Node-local, 24 hours, successful calls only |
| Retention | Contract-level only; no archive tier. Backups of the storage volume are outside the node |
| Clocks | Required: 5-minute freshness window for both lanes |
| Async size | Whole package in memory as one message |

### Planned work

| Item | Why |
|---|---|
| Client-certificate authentication at the connector | Defence in depth beside message signatures; needs per-deployment trust-store management |
| Encrypt identity private keys at rest | Keys are stored as PEM text; use the KMS abstraction already in the codebase or an external KMS |
| Shared state for scale-out | Required before running more than one node process per database |
| Archive tier for retention | Retention deletes; the console's archive fields are not backed by a job |
| Longer or cross-node idempotency | Only if callers need windows beyond 24 hours |
| Signed bootstrap | Possible once the partner's key is pre-registered on both sides |
| OpenAPI description of the Client API | None published |

## 14. Code map

| Concern | Where |
|---|---|
| Request filter, peer allow-list, signature check | `framework/InterceptingFilter`, `framework/PeerAuth`, `framework/ConsoleAuthFilter` |
| Session, cookies, token | `framework/InputProcessor`, `framework/JWTUtil`, `api/admin/Login` |
| First-time setup | `api/admin/RegisterAdmin` |
| Partners and handshake | `api/admin/Partners` |
| Contracts, participants | `api/admin/DataContract` |
| Async delivery, governance, retry, maintenance | `framework/TransferEngine`, `api/admin/DXManager` (inbound) |
| Sync delivery | `framework/SyncEngine` |
| Client API | `api/client/DX` |
| Path confinement | `framework/SafeFilePath` |
| Outbound peer client | `framework/P2PClient` |
| Schemas and migrations | `db/`, `web/WEB-INF/validator/` |
| Consent channel: system contract, ids, schema, sync with partners | `framework/CefEvents` (called from `api/admin/DXManager`, `DataContract`, `Partners`, `AppManager`) |
| Consent Channel console screen | `web/consent.html` |

---

## 15. Consent channel (CEF-EVENTS)

Consent and erasure travel on their own channel, separate from data, so that data contracts, the engines and the validation of data transfers stay exactly as they were. Use is in the [Consent and Erasure Guide](../guides/consent-and-erasure-guide.md); the format is the [Consent Exchange Format spec](../guides/consent-exchange-format.md).

### 15.1 Model

Every node owns one built-in async contract named `CEF-EVENTS`, read-only and open to every **Active** partner. A fiduciary's system sends [CEF](../guides/consent-exchange-format.md) JSON documents (consent granted, modified or withdrawn, erasure requested) to a processor node's `CEF-EVENTS`. The processor sends `ERASURE_CONFIRMED` to the fiduciary node's `CEF-EVENTS`, so one contract per node serves both directions. A data record and its consent are joined by the receiving application on `principal_id`, which data contracts carry as an ordinary, unmasked field.

The node does two things with a CEF document: it checks the **shape** (valid JSON, `cef_version` `1.x`, a non-empty `events` array, and `event_id`, `event_type`, `event_time`, `fiduciary_id` and `principal_id` on each event), and it delivers it like any async transfer. It does **not** decide whether a consent is granted, withdrawn or expired, it adds no consent rule to data transfers, and it does not delete a processor's data. Those belong to the processor's application.

### 15.2 How it is built on the existing contract model

- **Contract ids are derived from the owning node.** The id of a node's `CEF-EVENTS` is the name-based UUID of `tsi-dx-cef-events:<node_id>`. A sender can therefore address a partner's contract without a lookup or an invitation, and two nodes never create the same id.
- **Each node keeps copies.** A sender governs and records a transfer against its own copy of the contract, as for any invited contract. `CefEvents.sync()` makes sure each node has its own `CEF-EVENTS` and a read-only copy of each Active partner's, and keeps participants in step with partner status: an Active partner is an Active participant of the node's own contract, any other partner is suspended, and the node is an Active participant of each partner's copy. No invite/accept handshake is involved.
- **When it runs.** After a partner status change (handshake, termination), and lazily before listing contracts, creating an application, sending to a `CEF-EVENTS` contract, and checking a sender on the receive path. It is idempotent and cheap.
- **What is unchanged.** The receive path's participant check, signature verification, replay protection, sequence numbers and the transfer engine run as for any contract. `CEF-EVENTS` is the same kind of contract, with a fixed schema and no retention limit (payloads are kept so the consent screen and processors can re-read them).
- **Read-only.** Editing, suspending, or inviting nodes to a system contract is refused with `403`.

### 15.3 Console

The **Consent Channel** screen (`web/consent.html`) is a separate page. It sends events (guided form or pasted/uploaded JSON, with a live check), lists sent and received files with their delivery status. It reads transfers with `list_transfers` (which accepts an optional `contract_name` and `limit`, and returns `contract_id` and `contract_name`) and `get_transfer_payload`, and parses them in the browser. The screen shows delivery, not consent state: the node is a reliable courier and holds no consent store.

### 15.4 Decisions

**Separate channel, not consent in the data path.** Embedding consent in each record, or in a transfer header, would have put consent rules into data validation, a side file or header into every bulk push, and a consent flag on every contract. A separate channel leaves data transfers untouched; the cost is that the node cannot guarantee consent arrives before data. That guarantee belongs to the processor's application, and the audit trail shows the order afterwards.

**Full state per event, latest wins.** Every consent event carries the whole current state of one consent and replaces the earlier one, so there are no merge rules for two implementations to read differently.

**A system contract rather than a new message type.** Adding peer functions would have changed the peer channel. Reusing the contract model gave signing, ordering, retry, audit and the console's existing transfer views for free; the only new code is the seeding and the shape check.

**JSON only, async only, DX Nodes only.** CSV, the sync lane, and partners without a node are out of scope for this channel.

### 15.5 Limits

| Area | Limit |
|---|---|
| Shape only | Per-type fields (for example `consent_id` on a consent event) are checked by the receiving application |
| Whole document | A document is accepted or rejected as a whole; no per-event error report |
| Duplicates | The node does not track `event_id` or `request_id`; the processor ignores repeats |
| Ordering vs data | Consent is not guaranteed to arrive before the data it covers |
| Erasure | The processor deletes and confirms; the node cannot reach the processor's other systems |
| Console view | Reads the 200 most recent `CEF-EVENTS` transfers and parses them in the browser |

