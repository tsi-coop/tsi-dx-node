# Asynchronous Integration Guide

How an application sends data over the async (batch) lane: set up a contract, submit a package, track it, and what to do when it fails. For how the lane works internally see [Architecture §6](../design/architecture.md#6-asynchronous-lane). For a hands-on walk-through on two local nodes see the [Local Testing Guide](local-testing-guide.md) §10, or run [`examples/scripts`](../../examples/scripts/README.md).

**Use async for** loan application files, repayment schedules, reconciliations and any bulk or PII-heavy data. **Contract `interaction_type`:** `async` (the default).

## 1. Prerequisites

1. The two nodes are registered partners and the handshake is complete (partners `Active` on both).
2. The **receiving** node has created a contract with `interaction_type: async`, invited your node, and your node has accepted. The contract is `Active` on both.
3. On **your** node an application exists, is bound to that contract, and has an API key and secret.

## 2. Contract fields that matter

Created on the receiving node:

| Field | Meaning |
|---|---|
| `schema_definition` | JSON Schema (draft-07) for `json`; a `fields` list of column names for `csv` |
| `metadata.format` | `json` (default) or `csv` |
| `metadata.governance_rules.pii_anonymization` | Map of field/column name → `MASK`, `HASH`, `TOKENIZE` or `NONE` |
| `retention_policy_days` | Days a finished payload is kept before the purge deletes it. Omit to keep indefinitely; `0` purges at the next maintenance run |

`MASK` keeps the last four characters (`****1234`), `HASH` is SHA-256 hex, `TOKENIZE` is a deterministic token. CSV contracts require the header row to match the schema's field list exactly.

## 3. Submit a package

```bash
curl -s -X POST http://<node>/api/client/dx \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <api-key>" \
  -H "X-API-Secret: <api-secret>" \
  -d '{
    "_func": "initiate_transfer",
    "contract_id": "<async-contract-uuid>",
    "file_name": "loans-2026-10-12.json",
    "file_data": "<base64 of the file>"
  }'
```

```json
{ "success": true, "transfer_id": "…", "message": "Single-package payload accepted for processing." }
```

| Rule | Detail |
|---|---|
| `file_name` | A plain file name. Path separators, `..`, `:` and control characters are refused with `400` |
| `file_data` | Raw Base64 or a `data:...;base64,` URI. For `json` contracts the content must parse as JSON or the call is refused with `400` before anything is staged |
| Receiver | Taken from the contract, never from the request |
| Contract | Must be `Active`, `async`, and bound to the application; otherwise `403` |

The call returns as soon as the package is staged. Governance, sequencing and delivery happen in the background.

## 4. Client API functions

| `_func` | Purpose |
|---|---|
| `list_contracts` | Contracts this application may use |
| `get_contract_inspector` | Schema, governance rules and participants for one contract |
| `initiate_transfer` | Submit a package (above) |
| `get_transfer_status` | Status and failure reason for a `transfer_id` |
| `view_forensic_payload` | The governed payload as sent or received; the access is audit-logged |

Administrators can do the same in the console under **Transfer Logs**, where each transfer shows direction, counterparty, status and failure reason and its governed payload can be inspected.

## 5. Track it

```bash
curl -s -X POST http://<node>/api/client/dx -H "Content-Type: application/json" \
  -H "X-API-Key: <api-key>" -H "X-API-Secret: <api-secret>" \
  -d '{"_func":"get_transfer_status","transfer_id":"<transfer_id>"}'
```

| Status | Meaning | What to do |
|---|---|---|
| `Pending` | Staged, waiting for a worker, or waiting for the next retry (`error` says which attempt) | Wait |
| `Processing` | Being governed and sent | Wait |
| `Delivered` | Receiver acknowledged | Done |
| `Failed` | See `error` | Correct the cause and submit a new transfer |

### Failure reasons

| `error` starts with | Cause | Retried? |
|---|---|---|
| `Governance Error: Contract Violation ...` | Payload broke the schema | No: fix the data |
| `Peer unreachable ...` / `Peer returned HTTP 5xx` | Receiver down or failing | Yes: 30 s, 2 min, 8 min, 32 min, then `Failed` |
| `Peer Rejected Protocol: HTTP 400 ...` | Receiver refused the payload: schema violation, or a PII field not anonymised | No |
| `Peer Rejected Protocol: HTTP 401 / 403 ...` | Signature, participant, contract state, or replay rejection | No |
| `Staged payload missing` | Staged file was removed (for example by retention) | No |

A retry never re-applies governance and never creates a duplicate on the receiver.

## 6. Operating notes

- **Order.** Transfers on one contract to one receiver are sent one at a time, in order.
- **Clocks.** Keep node clocks synchronised (NTP): messages more than 5 minutes off are refused.
- **Size.** The whole package is held in memory and sent as one Base64 JSON message. Split very large datasets into several packages.
- **Storage.** Staged and received files live in the node's active storage path (`TSI_EXPORT_PATH`), which should be a persistent volume.
- **Retention.** Finished payloads older than the contract's `retention_policy_days` are deleted by the hourly maintenance job and the transfer is marked `Purged`; the metadata row stays. A purged payload can no longer be inspected.
