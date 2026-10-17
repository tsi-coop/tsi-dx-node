# Changelog

All notable changes to TSI DX Node are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 0.2.1 were not formally versioned and are not itemised.

## [0.3.0] - Unreleased

Adds the consent channel: nodes can now exchange consent and erasure events as well as data, which extends the node from data exchange into consent-aware data exchange. No database migration; existing data contracts and transfers are unchanged.

### Added

- **Consent channel (`CEF-EVENTS`).** Every node has a built-in, read-only async contract that carries Consent Exchange Format (CEF) v1 JSON between Active partners: consent granted, modified or withdrawn, erasure requested and confirmed. It needs no invitation or acceptance. The node checks only the shape of a CEF document and never judges consent; data contracts and data-transfer validation are unchanged. See [Architecture §15](docs/design/architecture.md#15-consent-channel-cef-events).
- **Consent Channel screen** (`/consent.html`): send events, see sent and received files, the latest consent state per consent, and erasure requests with their confirmations. No existing page changed.
- **Documentation:** [Consent Exchange Format spec](docs/guides/consent-exchange-format.md), [Consent and Erasure Guide](docs/guides/consent-and-erasure-guide.md), [CEF to CMS Mapping](docs/guides/cef-cms-mapping.md).
- **Example script** `examples/scripts/07-consent-exchange.sh`, included in `run-all.sh`.
- `list_transfers` accepts optional `contract_name` and `limit` (up to 500) and now also returns `contract_id` and `contract_name`.

### Changed

- Editing, suspending or inviting nodes to a built-in system contract is refused with `403`.

### Upgrade notes

- No database migration. The `CEF-EVENTS` contracts are created automatically: when a partnership becomes Active, or, on a node with partnerships already Active, the first time the contract list is opened, an application is created, or a CEF file is sent or received.
- Both nodes of a partnership need 0.3.0 to exchange CEF documents.

## [0.2.1] - 2026-10-12

First formally versioned release. It hardens authentication on both the console and the node-to-node channel, makes the receiver enforce its own contracts, adds delivery reliability to the async lane and idempotency to the sync lane, and reorganises the documentation.

### Upgrade notes

Read these before upgrading a running node.

- **Both nodes of a partnership must run 0.2.1.** Node-to-node requests are now signed and unsigned peer calls are refused with `401`. For a rolling upgrade only, set `TSI_DX_NODE_P2P_SIGNATURES=optional` on the upgraded node and remove it once both sides are on 0.2.1.
- **A JWT secret is now mandatory outside development.** Set `TSI_DX_NODE_JWT_SECRET` (32+ characters) or the node refuses to start. Sample placeholder values are rejected. With `TSI_DX_NODE_ENV=local|development|dev`, a random per-process key is used and admin sessions end on restart.
- **First-time setup needs a setup token.** Set `TSI_DX_NODE_BOOTSTRAP_TOKEN`; `init.html` and `registeradmin` require it.
- **Compose variable:** `docker-compose.yml` now reads `TSI_DX_NODE_JWT_SECRET`, falling back to the older `TSI_PRIVACY_VAULT_JWT_SECRET`. It no longer supplies a default secret.
- **Existing admin sessions end.** Console pages now use an `HttpOnly` session cookie set at login.
- **Database:** `retry_count` and `next_retry_at` are added to `data_transfers`. The node applies this at start-up; `db/05_transfer_retry.sql` is provided for fresh installs. No manual step.
- **Contracts created before this release** have no stored retention period (it was never saved) and are therefore kept indefinitely until one is set.

### Security

- **Signed peer messages.** Every node-to-node request carries a signature made with the sender's identity key, verified against the registered partner key, with a 5-minute window, single-use request ids, target binding and a check that `sender_node_id` matches the signer. `probe` and `receive_partnership_proposal` remain unsigned bootstrap calls. The fixed `X-DX-P2P-HANDSHAKE` header is now only a routing marker.
- **Contract notifications are authorised against the signer.** `notify_contract_suspended`, `notify_participant_suspended` and `receive_contract_update` are accepted only from the node that owns the contract, and `confirm_invitation` / `decline_invitation` only from the invitee they speak for. Previously any registered partner could send them for a contract it did not own.
- **Peer allow-list.** The handshake header bypasses admin authentication only for the inbound peer functions of each route; every other admin function always requires a token.
- **Console gating.** The eight console pages are served only to authenticated sessions (server-side filter, redirect to login, `Cache-Control: no-store`). Login sets an `HttpOnly`, `SameSite=Lax` cookie; `DELETE /api/admin/login` logs out and clears it.
- **First-time setup protection.** Requires the setup token (constant-time comparison, checked before the database), runs serialisably so racing setups cannot both succeed, and returns generic errors.
- **Path traversal fixed.** `file_name` must be a single plain name and the resolved path must stay inside the storage directory, on the Client API, the console upload, the receiver's inbound handler and every read of a stored file.
- **JWT signing key.** The built-in fallback secret is removed.
- **Directory listings** are disabled.

### Added

- **Receiver-side enforcement.** The receiving node validates inbound async payloads and sync requests against its own copy of the contract (L1) and verifies that every anonymised field is in its declared mask/hash/token form (L2). Violations get `400` and are audited (`SECURITY_CONTRACT_VIOLATION`). It also checks it is the contract's receiver and that the contract is Active and of the right type.
- **Async retry.** Transport failures, `5xx`, `408` and `429` are retried with backoff (30 s, 2 min, 8 min, 32 min; five attempts). Retries never re-apply governance, and duplicate deliveries are acknowledged rather than stored twice.
- **Retention purge.** A maintenance job (default hourly, `TSI_DX_NODE_MAINTENANCE_SECONDS`) deletes payloads older than the contract's `retention_policy_days` and marks the transfer `Purged`; also removes expired sync nonces. `run_maintenance` on `/api/admin/transfers` runs it on demand.
- **Sync idempotency.** An `idempotency_key` that already succeeded within 24 hours returns the recorded response with `idempotent_replay: true`; the same key with a different request is `400`.
- **Edit contract.** The receiving node can edit a contract (`update_contract`, and an **Edit** action in the console). Name, retention, and for sync contracts the responder URL and timeout can change while the contract is Draft or Active; participants are told of the shared ones (`receive_contract_update`, never the responder URL). Schema, anonymisation rules and PII fields can change only while the contract is a Draft nobody has been invited to, because partners agree to those; after that, create a new contract. `GET get_contract` now returns `retention_policy_days`.
- **Example scripts** (`examples/scripts/`): node setup, identity and partner handshake, contract definition, async transfer, sync call, and `06-negative-tests.sh` with 95 scenarios (92 by default, 3 more with `--circuit-breaker`); `run-all.sh`; teardown instructions.
- `SECURITY.md` and `docs/guides/security-hardening-guide.md`.

### Changed

- **L2 is applied once.** The sender transforms, the receiver verifies. Previously both ends applied the rules, so a `HASH` field was hashed twice on the sync lane.
- **Sequence numbers** are allocated and consumed under a lock per contract and receiver, so concurrent transfers no longer collide and arrive in order.
- **Pending sweep** runs every 30 seconds (was every 2 minutes) and starts transfers with an atomic claim, so two workers never run the same transfer.
- **Sync caller** applies governance before the circuit-breaker check, so an invalid payload is a `400` even when the circuit is open.

### Fixed

- Contract `retention_policy_days` entered in the UI was never saved; it is now stored and sent to participants in the invitation.
- The async fail-fast JSON check never matched (it compared against `"format":"json"` while the database returns `"format": "json"`), so non-JSON data was accepted on JSON contracts.
- An async transfer could be initiated on a `sync` contract.
- A sequence-number collision could fail the second of two simultaneous transfers as a replay.
- Sync responses with `HASH` rules were hashed twice.
- A sync contract could be created without a responder URL, become Active, and then fail every call with `503`. `create_contract` now refuses it with `400`, the console wizard requires the field, and the receiver records the `503` in its `sync_audit_log` instead of leaving no trace.
- Validation errors from contract functions returned `500`; they now return `400` with the message.
- **Transfer Logs** is organised by lane: **Async** (with All / Pending / Completed / Failed filters and counts) and **Sync**. The Completed filter now includes `Received` transfers, so a receiving node no longer shows an empty Completed list, and Pending includes `Processing` and retrying transfers.
- The console session cookie is `SameSite=Lax` (was `Strict`): opening a console link from another application no longer drops you on the login page although the session was still valid.
- Console sessions of two nodes on the same host (for example `localhost:8082` and `localhost:8083`) overwrote each other's cookie and logged you out. The session cookie is now named per node (`console_session_<tag>`). Everyone signs in once more after upgrading.

### Documentation

- `docs/` reorganised into `design/` (single `architecture.md`, replacing the transfer, sync and async design documents and the two historical plans) and `guides/` (local testing, security hardening, asynchronous and synchronous integration). `Local_Testing_Guide.md` moved to `docs/guides/local-testing-guide.md`.
- README: two exchange lanes, getting started with prerequisites and a setup-token step, documentation table, security section. The security guide documents the setup token's lifecycle (set, initialise, remove).

[0.3.0]: https://github.com/tsi-coop/tsi-dx-node/releases/tag/v0.3.0
[0.2.1]: https://github.com/tsi-coop/tsi-dx-node/releases/tag/v0.2.1
