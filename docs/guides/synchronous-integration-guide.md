# Synchronous Integration Guide

How an application makes real-time, governed request/response calls over the sync lane, and what a service has to provide to answer them. For how the lane works internally see [Architecture §7](../design/architecture.md#7-synchronous-lane). For a hands-on walk-through on two local nodes see the [Local Testing Guide](local-testing-guide.md) §11, or run [`examples/scripts`](../../examples/scripts/README.md).

**Use sync** when something is blocked on the answer and the payload is small: an eligibility check, an identity validation, a decision. Calls are bounded by a timeout (default 10 s). If the receiving system cannot answer inside that window, use the async lane.

"Real-time" here means synchronous request/response between two nodes. It is not streaming, pub/sub or webhook push.

## 1. Set up a sync contract

On the **receiving** node (the one that hosts the service), create a contract with `interaction_type: sync`. In the UI: **Data Contracts → New Contract → Interaction Type: Sync**.

| Field | Where | Meaning |
|---|---|---|
| `interaction_type` | contract | `sync` (default is `async`) |
| `schema_definition` | contract | JSON Schema (draft-07) the request must satisfy (L1) |
| `metadata.governance_rules.pii_anonymization` | contract | Per-field L2 rules applied to the request and the response |
| `metadata.sync_responder_url` | contract, receiver only | Internal endpoint the request is forwarded to |
| `metadata.sync_timeout_ms` | contract | Per-call budget in milliseconds. Default `10000` |

The responder URL is mandatory: a sync contract without one is refused at creation. You can change it later, and the timeout, with **Edit** on the contract (receiver only); the URL is never sent to callers.

Then invite the calling node(s), have them accept, and bind the calling application to the contract under **Applications** so its API key is authorised for it. `sync_responder_url` is never sent to the caller.

## 2. What the responder must do

The receiving node sends one `POST` with `Content-Type: application/json`; the body is the governed request payload. The responder must:

- return an HTTP `2xx` within `sync_timeout_ms`, and
- return a JSON **object** as the body.

Anything else is a failure: the receiving node answers `502` for a non-2xx status or `504` for no answer in time. The responder receives no DX credentials; restrict it by network placement (reachable only from the node).

The receiving node anonymises the responder's answer according to the contract before returning it, so a responder may return identifiers in clear and rely on the contract's `pii_anonymization` rules.

## 3. Make a call

Applications call their **own** node; the node handles the peer hop.

```bash
curl -s -X POST http://<node>/api/client/dx \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <api-key>" \
  -H "X-API-Secret: <api-secret>" \
  -d '{
    "_func": "execute_sync_request",
    "contract_id": "<sync-contract-uuid>",
    "request_payload": { "customer_id": "C-001", "mobile": "9876543210", "product": "loan" },
    "idempotency_key": "order-7731"
  }'
```

```json
{ "success": true, "response_payload": { "eligible": true, "limit": 250000 }, "duration_ms": 142 }
```

| Input | Required | Notes |
|---|---|---|
| `contract_id` | yes | An **Active** `sync` contract bound to the application, with this node an Active participant |
| `request_payload` | yes | JSON object; validated against the contract schema before it leaves your node |
| `idempotency_key` | no | Makes the call safe to retry (below) |

The returned `response_payload` is the governed response: PII fields are already masked per the contract.

### Idempotency

If you supply an `idempotency_key` and a call with that key already **succeeded** in the last 24 hours, the recorded response is returned with `"idempotent_replay": true` and `duration_ms: 0`, and the partner is not called again. The same key with a different request is refused with `400`. Failed calls are not recorded as done, so retrying a failure with the same key runs it again.

## 4. Errors

| Situation | Seen by caller |
|---|---|
| Missing or invalid `X-API-Key` / `X-API-Secret` | `401` |
| App not bound, contract not Active, or not `sync` | `403` |
| `contract_id` or `request_payload` missing | `400` |
| Request fails the contract schema (L1) | `400`, `Contract Violation: ...` |
| Same `idempotency_key`, different request | `400` |
| Circuit open for that partner | error, immediately (`Circuit open for partner ...`), no network call |
| Partner unreachable, rejected the call, timed out, or answered in violation of the contract | error; audited and counted toward the circuit breaker |

On the peer hop the receiving node answers `401` for a bad signature, `403` for a replayed nonce or a non-participant, `400` for a request that fails its own schema or sends PII in clear, `502` for a non-2xx responder, `503` if the contract has no `sync_responder_url`, and `504` for a responder timeout. These reach the application as an error from its own node.

## 5. Resilience

- **Timeout:** `metadata.sync_timeout_ms`, applied to the peer hop and the responder call.
- **Circuit breaker:** per partner, in memory on the calling node. After 5 consecutive failures calls fail immediately; after 60 s one attempt is let through and a success closes it. It is per partner, so one failing contract can open it for the others to that partner.
- **No automatic retry.** Retry policy belongs to the caller; use `idempotency_key` to make retries safe.

## 6. Audit trail

Both nodes write one `sync_audit_log` row per call: `contract_id`, `idempotency_key`, governed `request_payload`, governed `response_payload`, `sender_node_id`, `receiver_node_id`, `duration_ms`, `status` (`SUCCESS` / `TIMEOUT` / `ERROR`), `error_detail`, `timestamp`. Payloads are stored post-anonymisation; the log never holds the raw PII the contract masks. View them under **Transfer Logs → Sync**; the dashboard shows a 24-hour counter.
