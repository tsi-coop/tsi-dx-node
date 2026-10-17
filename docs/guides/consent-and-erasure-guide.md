# Consent and Erasure Guide

How to share consent, consent changes and erasure requests between two DX Nodes, and how a receiving system should use them. The format itself is in the [Consent Exchange Format (CEF) spec](consent-exchange-format.md). For the design see [Architecture §15](../design/architecture.md#15-consent-channel-cef-events). For the TSI DPDP consent management system see [CEF to CMS Mapping](cef-cms-mapping.md).

## 1. How it works

Consent and data travel on **two separate channels** between the same two nodes.

```
                 DATA CHANNEL (your data contracts, unchanged)
Sender app  ── records carry principal_id ──────────────▶  Processor app
                                                              │ joins on principal_id
Sender CMS  ── CEF-EVENTS (built in) ───────────────────▶  Processor consent store
               CONSENT_GRANTED / MODIFIED / WITHDRAWN
               ERASURE_REQUESTED
            ◀── ERASURE_CONFIRMED ──────────────────────────┘
                 CONSENT CHANNEL
```

- Every node has a built-in async contract named **`CEF-EVENTS`**. It needs no setup, no invitation and no acceptance: any **Active** partner can send to it.
- The node checks only that a file is well-formed CEF v1. It **never** decides whether a consent is valid, and it adds **no** consent check to your data contracts. The processor's application reads the consent and respects it.
- Each event is a normal signed, audited transfer, so the record of who sent which consent event to whom, and when, is kept like any other transfer.

**Your data contracts need one convention:** the data schema includes `principal_id`, sent as is (not masked or hashed), so the processor can link each record to its consent. `principal_id` is an opaque business id such as a customer, account or vendor id. The contract's name or description should state the `purpose_id` it serves.

## 2. Prerequisites

1. The two nodes are Active partners (handshake complete).
2. Nothing to create. The `CEF-EVENTS` contracts appear on both nodes as soon as the partnership becomes Active. On a node upgraded with partnerships already Active, they are created the first time the contract list is opened, an application is created, or a CEF file is sent or received.
3. **Sending from an application (a CMS):** an application on your node, bound to the partner's `CEF-EVENTS` contract, with an API key and secret (section 3).
4. **Sending from the console:** an administrator can use the **Consent Channel** screen (section 7) instead.

## 3. Find the contract and set up the sender

Each node owns one `CEF-EVENTS` contract. To send to partner **B**, you use **B's** contract. Your node holds a read-only copy of it.

**Find it in the console:** open **Data Contracts**. `CEF-EVENTS` appears once per Active partner, with that partner as the receiver.

**Find it through the API:**

```bash
curl -s -X POST http://<node>/api/admin/contracts \
  -H "Content-Type: application/json" -H "Authorization: Bearer <admin-token>" \
  -d '{"_func":"list_contracts"}' \
  | jq -r '.[] | select(.name=="CEF-EVENTS" and .receiver_node_id=="<partner-node-id>") | .contract_id'
```

**Or compute it.** The id is derived from the owning node's id, so you can work it out without calling anything: take the MD5 of `tsi-dx-cef-events:<node_id>`, set the version nibble to 3 and the variant bits to `10`, and format as a UUID.

```python
import hashlib, uuid
def cef_contract_id(node_id: str) -> str:
    b = bytearray(hashlib.md5(("tsi-dx-cef-events:" + node_id).encode()).digest())
    b[6] = (b[6] & 0x0f) | 0x30
    b[8] = (b[8] & 0x3f) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))
```

**Bind an application to it** (once per partner), as for any contract:

```bash
curl -s -X POST http://<node>/api/admin/apps -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"_func":"create_app","name":"cms-consent","description":"Consent sender",
       "authorized_contract_ids":["<partner CEF-EVENTS contract id>"]}'
# then generate_api_key for the returned app id (see the Asynchronous Integration Guide)
```

## 4. Send consent

Submit a CEF document as an ordinary async transfer. The call returns as soon as the file is staged; delivery happens in the background, with the same retry as any async transfer.

```bash
curl -s -X POST http://<node>/api/client/dx \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <api-key>" -H "X-API-Secret: <api-secret>" \
  -d '{
    "_func": "initiate_transfer",
    "contract_id": "<partner CEF-EVENTS contract id>",
    "file_name": "cef-2026-10-17-001.json",
    "file_data": "<base64 of the CEF document>"
  }'
```

Track it with `get_transfer_status` (`Delivered` means the partner node accepted it). See the [Asynchronous Integration Guide](asynchronous-integration-guide.md) §3 to §5.

What to send:

| Situation | Send |
|---|---|
| A principal gives consent | One `CONSENT_GRANTED` event with the full `purposes` list |
| The principal changes it | `CONSENT_MODIFIED` with the **new full** `purposes` list |
| One purpose is withdrawn | `CONSENT_WITHDRAWN` with the full list, that purpose set to `withdrawn` |
| Everything is withdrawn | `CONSENT_WITHDRAWN` with every purpose `withdrawn` |
| The principal asks for erasure | `ERASURE_REQUESTED` with a `request_id` and a `deadline_at` |
| Initial load of existing consents | One document with many events, or several documents. A one-off activity. |
| Day to day | A nightly feed, or near real-time, one small document per change |

Send the consent **before** the data it covers. The node will not enforce the order (see section 8), but the processor will have nothing to join against otherwise.

A document is accepted or rejected as a whole. If it fails, the two parties fix it and resend.

### When a send fails

| Result | Meaning | Action |
|---|---|---|
| `400` on submit | `file_data` is not valid Base64 or not valid JSON | Fix the file |
| Transfer ends `Failed` with `Contract Violation` | The file is not CEF v1 (missing a required field, wrong `event_type`, wrong `cef_version`, empty `events`) | Fix the document and resend |
| `403` on submit | The application is not bound to that partner's `CEF-EVENTS`, or the partner is not Active | Bind the app (section 3), check the partnership |
| `Failed` after retries | The partner node was unreachable | Resend when it is back |

## 5. Receive and respect consent (the processor)

A processor node receives CEF documents as transfers on its own `CEF-EVENTS`. Collect them like any received async payload:

```bash
# 1. list transfers received on CEF-EVENTS
curl -s -X POST http://<node>/api/admin/transfers -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"_func":"list_transfers","contract_name":"CEF-EVENTS","limit":200}'

# 2. read one
curl -s -X POST http://<node>/api/admin/transfers -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"_func":"get_transfer_payload","transfer_id":"<transfer_id>"}'
```

`list_transfers` accepts an optional `contract_name` and `limit` (up to 500). Each row has `direction` (`Incoming` for received), `peer_node_id`, `status` (`Received`), `contract_id` and `contract_name`. The payload is the CEF document exactly as sent. `CEF-EVENTS` keeps payloads indefinitely, so you can re-read them.

Then apply the rules in [CEF spec §4](consent-exchange-format.md#4-processing-rules). In short, a processor should:

1. **Keep a consent store** keyed by `(fiduciary_id, principal_id, consent_id)`. For each consent event, keep the one with the latest `event_time`. It replaces everything earlier. There is no merging.
2. **Ignore repeats.** A repeated `event_id` has no extra effect.
3. **Join to data.** When data arrives on a data contract, look up each record's `principal_id` and the contract's `purpose_id`. Use the record only if the latest state for that purpose is `granted` and `expires_at` has not passed. Hold or reject the rest, and say so in the processor's policy.
4. **Apply changes as they arrive.** A withdrawal or modification changes what may be done with data already held, not only with new data.
5. **Handle erasure** (section 6).

A short reader that does steps 1 and 3 is in [CEF spec §9](consent-exchange-format.md#9-reference-reader).

**Sync lane.** Consent applies to real-time calls too, but the **caller** is responsible for it: the caller checks consent with its own CMS before it calls. The receiver's role is the lifecycle: applying updates, withdrawals and erasure from this channel.

## 6. Erasure

1. The fiduciary's CMS sends `ERASURE_REQUESTED` to the processor's `CEF-EVENTS`. It sets the `deadline_at` for that request and may limit the scope with `purpose_ids` and `data_categories`. No scope means everything held about the principal.
2. The processor's application finds the principal's data by `principal_id`, deletes what the scope covers, and removes it from its other systems. The node can only delete what the node stores; copies held elsewhere are the processor's to remove.
3. The processor sends `ERASURE_CONFIRMED` with the same `request_id` to the **fiduciary's** `CEF-EVENTS`: the sender of the request is now the receiver, and uses its own copy of the contract in the other direction. It may send `ACKNOWLEDGED` first and `COMPLETED` later. `REJECTED` (for example, no data held for that principal) and `UNDER_LEGAL_HOLD` explain why not.
4. The CMS reads the confirmation and updates its purge tracker. The CMS decides what happens after the deadline.

A processor should act only on principals whose data it received from that fiduciary.

## 7. The Consent Channel screen

An administrator can do all of this by hand at `/consent.html` (**Consent Channel** screen). It is reached by its URL, and uses the same login as the rest of the console.

| Tab | What it does |
|---|---|
| **Send** | Pick a partner and an event type, fill in the fields (a purposes grid for consent events), see the exact CEF JSON, and send. You can also paste or upload a hand-written or batch file, or load a sample. The page shows whether the file passes the node's check before you send. |
| **Sent** | Files this node sent: partner, time, event types, status, with the failure reason if any. Open one to see the events and the raw JSON. |
| **Received** | Files this node received, same layout. Files that fail the node's check are refused and never stored; those refusals are in the Audit Trail. |
| **Consent State** | The latest state per consent, built in the browser from received (or sent) events using the latest-wins rule. For inspection and testing. The processor's own application holds the real consent store. |
| **Erasure** | Requests joined to their confirmations by `request_id`, with the state: Open, In progress, Completed, Rejected, Failed, Legal hold, or Overdue (deadline passed without `COMPLETED`). |

To test between two nodes: on node A open **Send**, pick node B, load the *Grant (2 purposes)* sample and send. On node B, **Received** shows the file and **Consent State** shows the person with both purposes granted. Send *Withdraw one* from A: B's state now shows one purpose withdrawn. Send *Erasure request* from A, then *Erasure confirmed* from B: both **Erasure** tabs show it Completed.

## 8. What the node does and does not do

| The node does | The node does not |
|---|---|
| Deliver CEF documents signed, in order and with retry | Decide whether a consent is valid, withdrawn or expired |
| Check the shape of every CEF document (section 5 of the spec) | Check that consent exists before a data transfer. Data contracts are unchanged. |
| Refuse non-CEF files on the sender and again on the receiver | Track `event_id` or `request_id`. Duplicates are the processor's to ignore. |
| Keep `CEF-EVENTS` read-only: it cannot be edited, suspended or given invitations (`403`) | Delete a processor's data. The processor's application does that. |
| Record every transfer in the transfer log and audit trail | Guarantee consent arrives before data. The audit trail shows the order afterwards. |

## 9. Limits

- Async lane only. `CEF-EVENTS` is not available for sync calls.
- Only between DX Nodes. A partner without a node is not reached by this channel.
- A document is processed whole. There is no partial acceptance and no per-event error report.
- The Consent State and Erasure tabs read up to the 200 most recent `CEF-EVENTS` transfers and parse them in the browser. They are an inspection aid, not a consent store.
- Payload size follows the normal async limits ([Architecture §6.6](../design/architecture.md#66-payload-size)).

## 10. Try it end to end

[`examples/scripts/07-consent-exchange.sh`](../../examples/scripts/README.md) runs the whole flow on two local nodes: grant with two purposes, withdrawal, erasure request, confirmation, plus the failure cases. It needs only scripts 01 and 02 to have run (the nodes must be Active partners).
