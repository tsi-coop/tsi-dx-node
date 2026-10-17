# Plan: Consent and Erasure as a Separate Channel

Status: Steps 1 to 7 implemented and tested on two local nodes (see sections 13 and 14). The CMS pilot (step 8) remains. No change to the transfer engines. No change to data-transfer validation.

## 1. Idea in one paragraph

Consent and data travel on **two separate channels**. The data channel is exactly what DX Node does today. The consent channel is a built-in system contract on every node, `CEF-EVENTS`, that carries a standard **Consent Exchange Format (CEF)** in JSON. The sender's CMS shares new consents, modifications, withdrawals and erasure requests with any Active partner over this channel, the same way data is shared. The receiver (the data processor) joins the two by `principal_id`, the CMS link key across all systems, and respects the consent. The node adds no validation to data transfers and never judges consent.

```
                  DATA CHANNEL (unchanged)
Sender app  ── contract: loan-data  ──────────────▶  Processor app
                records carry principal_id                    │ joins on
                                                              │ principal_id
Sender CMS  ── CEF-EVENTS (built in) ─────────────▶  Processor consent store
                CONSENT_GRANTED / MODIFIED / WITHDRAWN        │
                ERASURE_REQUESTED                             │
            ◀── ERASURE_CONFIRMED ────────────────────────────┘
                  CONSENT CHANNEL
```

## 2. What changes in DX Node

| Area | Change |
|---|---|
| Transfer engines (async, sync), peer channel, signing | **None.** |
| Data contracts and data-transfer validation | **None.** No flag, no consent rule. |
| `CEF-EVENTS` system contract | The one code change. Seeded on every node at start-up, read-only, with the JSON event schema of section 3. JSON only, no CSV. Every Active partner may send to it with no invitation. |
| Consent judgement | **None.** The node checks the event is well formed, like any schema check, and nothing more. |
| Admin console | One new page, `consent.html` (section 7). No existing page changes. |
| Docs and examples | CEF spec, sample files, guide, example script, CMS mapping. |

A node owns its own `CEF-EVENTS` and receives events there from partners. So events flow to a processor's `CEF-EVENTS`, and replies flow back to the sender's `CEF-EVENTS`. One contract serves both directions.

## 3. Consent Exchange Format (CEF) v1

JSON only. Field names follow the `tsi-dpdp-cms` artifacts (`consent_records`, `record_consent`, `withdraw_consent`, `initiate_purge_request`, `confirm_purge_status`) so a CMS can export without remapping.

### 3.1 Envelope

A request holds one or many events, so consents can be shared in batches. A batch is accepted or rejected as a whole, because the node checks only the four fields in 3.2 for every event. A batch may be as large as the node's normal payload limit. If a batch fails, the two parties fix it and resend. There is no partial acceptance and no per-event error report. Large batches are expected for one-time loads. Day-to-day, consents arrive as a nightly feed or as near real-time async events.

```json
{ "cef_version": "1.0", "events": [ ... ] }
```

### 3.2 Event fields

| Field | Required | Notes |
|---|---|---|
| `event_id` | yes | Unique per sender. A repeat has no extra effect. |
| `event_type` | yes | `CONSENT_GRANTED`, `CONSENT_MODIFIED`, `CONSENT_WITHDRAWN`, `ERASURE_REQUESTED`, `ERASURE_CONFIRMED` |
| `event_time` | yes | ISO 8601 UTC |
| `fiduciary_id` | yes | A unique string identifying the data fiduciary the consent belongs to. |
| `principal_id` | yes | The CMS `user_id`, the link key across all systems. An opaque id such as customer id, account id or vendor id. |
| `consent_id` | consent events | `consent_records.id`. One consent can cover several purposes. |
| `granted_at` | `CONSENT_GRANTED`, `CONSENT_MODIFIED` | ISO 8601 UTC |
| `purposes` | consent events | Array of purposes, see 3.3. |
| `request_id` | erasure events | `purge_requests.id` |
| `trigger` | `ERASURE_REQUESTED` | `ErasureRequest`, `ConsentWithdrawal`, `RetentionPolicyExpiry` |
| `purpose_ids`, `data_categories` | no, `ERASURE_REQUESTED` | Scope of the erasure (`processing_purposes_affected`, `data_categories_to_purge`). Empty means everything held about the person. |
| `deadline_at` | `ERASURE_REQUESTED` | Set by the sender, per request. |
| `reply_status` | `ERASURE_CONFIRMED` | `ACKNOWLEDGED`, `COMPLETED`, `REJECTED`, `UNDER_LEGAL_HOLD`, `FAILED` |
| `records_affected_count`, `details`, `error_message`, `confirmed_by`, `confirmed_at` | `ERASURE_CONFIRMED` | Match `confirm_purge_status`. |

The node checks only that the JSON is valid and that each event has `event_id`, `event_type` (one of the five values), `event_time`, `fiduciary_id` and `principal_id`. The per-type fields are checked by the **receiving application**, not the node.

### 3.3 Purposes inside a consent

A consent carries a list of purposes, so one consent can cover several uses.

| Field | Required | Notes |
|---|---|---|
| `purpose_id` | yes | A unique string. Matches the purpose named on the data contract. |
| `status` | yes | `granted`, `denied`, `withdrawn`, `expired` |
| `expires_at` | no | Empty means until withdrawn. Not judged by the node. |
| `data_categories` | no | `data_point_id` values this purpose covers |

How consent events are read:

- **Every consent event carries the complete current state of its `consent_id`**: the full `purposes` list with a status on each. The latest event for a `consent_id` replaces all earlier ones. Nothing is merged.
- `CONSENT_GRANTED`, `CONSENT_MODIFIED` and `CONSENT_WITHDRAWN` are labels for why the state changed. They are informational. The processor applies them all the same way.
- To withdraw one purpose, send the full state with that purpose set to `withdrawn`. To withdraw everything, send every purpose as `withdrawn`.
- A purpose that is not in the latest state is not consented.

### 3.4 Example

```json
{ "cef_version": "1.0", "events": [
  { "event_id": "e-1", "event_type": "CONSENT_GRANTED", "event_time": "2026-10-01T09:00:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3", "consent_id": "c-77", "granted_at": "2026-10-01T09:00:00Z",
    "purposes": [
      { "purpose_id": "loan_underwriting", "status": "granted",
        "expires_at": "2027-10-01T09:00:00Z", "data_categories": ["income", "pan"] },
      { "purpose_id": "credit_marketing", "status": "granted", "data_categories": ["email"] } ] },
  { "event_id": "e-2", "event_type": "CONSENT_WITHDRAWN", "event_time": "2026-10-17T10:00:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3", "consent_id": "c-77", "granted_at": "2026-10-01T09:00:00Z",
    "purposes": [
      { "purpose_id": "loan_underwriting", "status": "granted",
        "expires_at": "2027-10-01T09:00:00Z", "data_categories": ["income", "pan"] },
      { "purpose_id": "credit_marketing", "status": "withdrawn", "data_categories": ["email"] } ] },
  { "event_id": "e-3", "event_type": "ERASURE_REQUESTED", "event_time": "2026-10-17T10:05:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3", "request_id": "r-31", "trigger": "ErasureRequest",
    "purpose_ids": ["credit_marketing"], "deadline_at": "2026-10-27T10:05:00Z" } ] }
```

Reply:

```json
{ "cef_version": "1.0", "events": [
  { "event_id": "e-9", "event_type": "ERASURE_CONFIRMED", "event_time": "2026-10-20T08:00:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3", "request_id": "r-31", "reply_status": "COMPLETED",
    "records_affected_count": 4, "details": "Marketing records deleted",
    "confirmed_by": "processor-ops", "confirmed_at": "2026-10-20T08:00:00Z" } ] }
```

## 4. How it works end to end

1. **Data contract.** Defined as today. The data schema includes `principal_id` as a field, sent as is (not masked or hashed), so the processor can link each record to a person. It is an opaque business id, such as customer id, account id or vendor id. Without it the processor cannot use the data. The contract's name or description states the `purpose_id` it serves. Nothing consent-related is set on the contract.
2. **Give consent.** The sender's CMS sends `CONSENT_GRANTED` events to the partner's `CEF-EVENTS`, one per consent, or a batch of many. The processor stores them by `principal_id` and `purpose_id`.
3. **Share data.** The sender sends data as today. The node does no consent check.
4. **Respect.** The processor application joins each record to the consent for its `principal_id` and the contract's purpose, and acts on it: use only for the agreed purpose, stop at `expires_at`, hold or reject records with no granted consent. This is the processor's duty, not the node's.
5. **Modify or withdraw.** `CONSENT_MODIFIED` or `CONSENT_WITHDRAWN` events on the same channel, for the whole consent or for chosen purposes. The processor updates its view.
6. **Erase.** `ERASURE_REQUESTED` goes to the processor's `CEF-EVENTS`. The processor deletes the person's data and sends `ERASURE_CONFIRMED` to the sender's `CEF-EVENTS`. The CMS maps it to `confirm_purge_status`.
7. **Evidence.** Every event is a normal signed, audited transfer. The record of who sent which consent event to whom, and when, is already kept.

An optional reference **CEF reader** (small script) can parse JSON events and print the current consent state per `principal_id` and `purpose_id`.

## 5. Rules of the road

- **Two channels, one link key.** `principal_id` is the only link between a data record and its consent.
- **Consent first is good practice, not enforced.** Send consent before the data. The node will not stop data arriving without consent. The processor should hold or reject such records, and should say so in its policy.
- **Sync lane.** The caller checks consent with its own CMS before it calls. That is the caller's responsibility. The receiver's responsibility is the lifecycle: applying updates, withdrawals and erasure from the channel.
- **Idempotent.** `event_id` and `request_id` are unique. A repeat is ignored.
- **Latest wins.** For each `consent_id`, the event with the latest `event_time` wins and replaces the whole state. Ties go to the later event in the file. An event older than the one already applied is ignored.
- **Scope.** A processor acts only on people it actually received data about from that sender. A request for anyone else is answered `REJECTED`. This is the processor's rule, not the node's.
- **Erasure depends on the processor.** It deletes and reports. The node cannot reach the processor's other systems.
- **Async lane only.** `CEF-EVENTS` is an async contract. The sync lane does not use it.
- **Versioned and compatible.** Within 1.x, readers ignore unknown fields and unknown event types, and new fields are additive and optional. A breaking change means `cef_version` 2.0.

## 6. Trade-off to accept

Because the channels are decoupled, the node cannot guarantee that consent reached the processor before the data. The earlier designs could, at the cost of validation in the data path. Under this plan that guarantee lives in the processor's application. The audit trail still shows exactly when each consent event and each data transfer arrived, so the order can be proved afterwards.

## 7. Console: a separate Consent screen

One new page, `web/consent.html`, holds everything. **No existing screen is changed.** It uses only existing API functions (`list_partners`, `list_contracts`, `initiate_transfer`, `list_transfers`, `get_transfer_payload`), so there is no new backend work. It finds the built-in `CEF-EVENTS` contract by its fixed name.

It is reached by its URL. Adding a sidebar link means a one-line edit in each existing page, so that is left as an optional follow-up.

| Tab | What it does |
|---|---|
| **Send** | Manual sending of consent events, mainly for testing. Pick the partner and event type, then fill in fiduciary, principal, consent id and a purposes grid (purpose, status, expiry, categories). A live JSON preview shows the exact CEF file. A paste or upload mode sends a hand-written or batch file. A **Send** button calls `initiate_transfer` on `CEF-EVENTS`. A "Load sample" button fills in the examples from section 3.4, including a withdrawal and an erasure request. |
| **Sent** | Events this node sent: partner, time, event count, event types, transfer status. A row opens the parsed events and the raw JSON. |
| **Received** | Events this node received, same columns, plus the result of the node's check for each file (accepted, or why it was refused). A row opens the parsed events and the raw JSON. |
| **Consent state** | A view built in the browser from the **Received** events: the latest state per `fiduciary_id`, `principal_id` and `consent_id`, with each purpose, its status, expiry and the last event time. This applies the "latest `event_time` wins" rule of section 5. It is for inspection and testing, not a source of truth. The processor's own application holds the real consent store. |
| **Erasure** | Joins `ERASURE_REQUESTED` events with `ERASURE_CONFIRMED` events by `request_id`: principal, partner, deadline, reply status. Requests past `deadline_at` without a `COMPLETED` reply are marked Overdue. |

**Manual end-to-end test, with two nodes (A sender, B processor):**

1. On A, open **Send**, choose partner B, load the sample `CONSENT_GRANTED` with two purposes, and send.
2. On B, open **Received**: the file appears, accepted. Open **Consent state**: the person shows two granted purposes.
3. On A, send a `CONSENT_WITHDRAWN` event with one purpose set to `withdrawn`. On B, **Consent state** now shows that purpose as withdrawn, and the event time is later.
4. On A, send an `ERASURE_REQUESTED`. On B, **Erasure** shows it as open.
5. On B, send an `ERASURE_CONFIRMED` for that `request_id` to A. On A, **Erasure** shows it as completed.
6. Negative checks: send a file with a missing `principal_id` or an unknown `event_type`. A shows it refused, B shows nothing received.

**Notes**

- Browser-side parsing is fine for hundreds of transfers. If volume grows, a small read function on the node can replace it later. It is not part of v1.
- The tabs read payloads, so `CEF-EVENTS` should keep payloads for a long time or indefinitely (retention setting). Otherwise old events show as purged.
- Payload views are audited like any payload inspection. Events hold only opaque ids.

## 8. Deliverables

| # | Item | Notes |
|---|---|---|
| 1 | `CEF-EVENTS` system contract | Seeded at start-up, read-only, open to Active partners, JSON schema. The only code change. |
| 2 | CEF spec | `docs/guides/consent-exchange-format.md`: section 3, finalised. |
| 3 | Samples | Valid and invalid JSON event files, including a multi-purpose consent and a partial withdrawal. |
| 4 | Guide | `docs/guides/consent-and-erasure-guide.md`: the flow in section 4 with `curl` examples, and how a processor should join consent to data. |
| 5 | Example script | `examples/scripts/07-consent-exchange.sh`: grant (several purposes), send data, partially withdraw, erase, confirm, using existing functions. |
| 6 | CMS mapping note | CEF fields to `tsi-dpdp-cms` tables and functions. |
| 7 | Reference reader (optional) | Parses CEF JSON, prints current state per person and purpose. |
| 8 | Consent screen | `web/consent.html`: Send, Sent, Received, Consent state, Erasure tabs (section 7). No other page changes. |
| 9 | Tests | Malformed JSON, unknown `event_type`, missing `principal_id`, duplicate `event_id`, partner not Active. Added to the negative tests. |

## 9. Phases

| Phase | What | Done when |
|---|---|---|
| 1 | Finalise CEF v1 with the CMS team. Publish spec and samples. | Both sides agree the fields. |
| 2 | Seed `CEF-EVENTS` with auto-access for Active partners. | Two nodes exchange a JSON event file with no contract set up. |
| 3 | Example script, guide, CMS mapping. | A grant, a withdrawal and an erasure go from the CMS to a processor and the confirmation reaches the purge tracker. |
| 4 | Consent screen. | The manual test in section 7 passes on two local nodes. |
| 5 | (Optional) Reference reader. | Decided after Phase 4. |

## 10. Implementation steps, in sequence

Each step is small and leaves the node working. Steps 1 to 4 are the node change. Steps 5 to 8 are the console, docs and tests.

| # | Step | Detail | Done when |
|---|---|---|---|
| 1 | **Spike: partner-to-partner send without an invitation** | On two local nodes, trace how a transfer is accepted: the participant check in `DXManager` (around line 231), the sequence number and replay check, and the sender-side contract lookup. Note exactly what blocks a send to a contract the sender was never invited to. | A short note listing the checks to relax for `CEF-EVENTS`, and confirming the change stays small. If it does not, stop and revisit the plan. |
| 2 | **Freeze the CEF v1 schema** | Write the JSON Schema for section 3 (envelope, the five-field check, `event_type` values, `purposes` shape). Review it with the CMS team. | The schema file is agreed and committed. Later changes follow the 1.x rules in section 5. |
| 3 | **Seed `CEF-EVENTS`** | Add a database migration (`db/06_*.sql`) or start-up seeding that creates the system contract on every node: fixed name, async, read-only, the schema from step 2, no retention limit. Mark it as a system contract so edit, suspend and delete are refused. | A fresh and an upgraded database both start, and `list_contracts` shows `CEF-EVENTS`. |
| 4 | **Open it to Active partners** | Apply the change found in step 1: for `CEF-EVENTS` only, a sender that is an Active partner is accepted as a participant on both the sending and receiving side, with no invitation. All other contracts keep today's rules. | Node A sends a valid event file to node B with no contract setup. A non-partner and a suspended partner are refused. Existing example scripts still pass. |
| 5 | **Example script and negative tests** | `examples/scripts/07-consent-exchange.sh` (grant with two purposes, send data, withdraw, erase, confirm). Add negative cases to `06-negative-tests.sh`: malformed JSON, unknown `event_type`, missing `fiduciary_id` or `principal_id`, duplicate `event_id`, inactive partner. | `run-all.sh` passes, including the new cases. |
| 6 | **Consent screen** | Build `web/consent.html` in this order: Send (with preview and samples), Sent, Received, Consent state, Erasure. Existing pages are not touched. | The manual two-node test in section 7 passes. |
| 7 | **Spec, guide and CMS mapping** | Write the CEF spec, the guide with `curl` examples, and the CMS field mapping. Link the spec from the architecture document. Add the `CHANGELOG.md` entry. | Docs reviewed, links work. |
| 8 | **Pilot with the CMS** | The `tsi-dpdp-cms` team exports consent events in CEF, sends them to a processor node, and sends an erasure request. The processor replies with a confirmation, and the CMS records it in its purge tracker. | One real grant, one withdrawal and one erasure complete end to end. |

**Optional after step 8:** a reference CEF reader script, a sidebar link to the Consent screen, and a node-side read function if browser-side parsing stops scaling.

**Order and dependencies:** 1 gates 3 and 4. 2 gates 3, 5 and 6. 3 and 4 gate 5 and 6. 5 and 6 can run in parallel. 7 can start once 2 is frozen and finishes after 6. 8 needs 4 and the CMS export.

## 11. After implementation: open the format to other vendors

Goal: other vendors (CMS products, data processors, other exchange platforms) adopt CEF, so consent and erasure interoperate beyond DX Node. This is reviewed after the implementation is done, not before. Nothing in the build depends on it.

What the design already gives us, and must keep:

- CEF is plain JSON with no dependency on DX Node. Any system that can send and receive JSON can use it.
- The 1.x compatibility rules (section 5) let vendors build against v1 safely.
- Field names follow the `tsi-dpdp-cms` artifacts, so there is a real implementation behind the format.

To review after implementation:

| Topic | Question to settle |
|---|---|
| Standalone spec | Publish CEF as its own document and JSON Schema, separate from the DX Node docs, with its own version number. |
| Licensing and governance | An open licence for the spec and schema. Who maintains it, and how changes are proposed and approved (for example a public repository with a change process). |
| Transport neutrality | CEF is defined without the DX Node transport. State how it can ride on other channels (HTTPS webhook, file drop, message queue) so vendors need not run DX Node. |
| Conformance | A small public test suite and sample files, so a vendor can show its files are valid. Possibly a "CEF compatible" statement. |
| Reference implementations | The reference reader, plus a sample sender and receiver, in a vendor-neutral repository. |
| Mapping to other standards | Check alignment with existing consent models (for example the DPDP Act and Rules terms, consent-artefact and receipt formats, and similar open specifications) and publish a mapping table. |
| Outreach | Share with CMS vendors, processors and industry or regulator groups, and collect feedback before any 2.0 change. |

Rule until then: no change to the CEF v1 field names or meaning for the sake of adoption. Feedback is collected for 1.x additions or 2.0.

## 12. Decisions

- `expires_at` is not judged by the node.
- `principal_id` is the CMS `user_id`, the link key across all systems.
- Consent, modification, withdrawal, erasure and replies all use the built-in `CEF-EVENTS` contract, open to any Active partner. No per-partner contract.
- `CEF-EVENTS` is JSON only. A consent carries a list of purposes.
- `purpose_id` is a unique string. Naming it on the data contract is enough to map a contract to a purpose.
- No consent flag or validation on data contracts.
- Sync lane: the caller checks consent with its CMS before calling. The receiver handles lifecycle (updates, withdrawal, erasure).
- The erasure deadline is set by the sender, per request.
- `principal_id` is an opaque business id (customer, account or vendor id), sent unmasked in data. `fiduciary_id` is a required unique string on every event.
- Every consent event carries the complete current state of its `consent_id`. The latest `event_time` wins. `event_id` is unique per sender.
- Consents can be shared in batches. A batch is accepted or rejected as a whole. A failure is fixed by the two parties and resent.
- `CEF-EVENTS` is async only. Within 1.x, unknown fields and event types are ignored.
- To check during implementation: letting every Active partner send to `CEF-EVENTS` against the participant check in `DXManager` and per-contract sequence numbers.
- The admin console gets one new, separate page, `consent.html`, built on existing API functions. No existing screen is changed. A sidebar link is an optional follow-up.
- Opening CEF to other vendors for interoperability is a stated goal, reviewed after implementation (section 11).
- Scope stays light for the BFSI segment: JSON and CSV only. Legacy formats and transports (FHIR, AS2, EDI) are not planned. AS2 was requested once and is kept as a lead. It is reconsidered only if a paying customer needs it, and a standalone AS2 gateway in front of the node is the first option. The consent channel does not depend on the data format, so this choice does not affect CEF.
- The CEF spec will live in `docs/`, linked from the architecture document. Only this plan is updated now. Docs and other places are updated after implementation.

No open questions at this stage. One item is checked during implementation (see above).

## 13. As built (steps 1 to 6)

What the spike found and how the code differs from the plan's wording:

- **Contract ids.** Contract ids are UUIDs and a sender governs and records a transfer against its own copy of the contract. So `CEF-EVENTS` has a deterministic id per owning node (a name-based UUID of `tsi-dx-cef-events:<node_id>`). A sender can address any partner's contract without a lookup, and two nodes never collide on the same id.
- **Local copies.** Each node keeps its own `CEF-EVENTS` plus a read-only local copy of each Active partner's, created by `CefEvents.sync()`. Step 7 added calls when a partner's status changes (handshake, termination, deletion) and when an application is created, so the contracts exist as soon as a partnership is Active. They are also created lazily before listing contracts, before sending to a `CEF-EVENTS` contract and before checking a sender on the receive path, which covers nodes upgraded with partnerships already Active. Participants are kept in step with partner status: an Active partner is an Active participant, any other partner is suspended.
- **Code touched.** New `framework/CefEvents.java` (ids, schema, sync). `DXManager` calls `syncIfCef` on the send and receive paths. `DataContract` calls `sync()` when listing and refuses edit, invite and suspend on a system contract (`403`). The receive-path participant check, replay protection, sequence numbers and the transfer engine are unchanged.
- **Schema check.** In addition to the five event fields, the node checks `cef_version` is `1.x` and `events` is a non-empty array. The sender runs the same check before sending, so a bad file ends as a `Failed` transfer on the sender and never reaches the receiver. The receiver repeats the check, as it does for any contract.
- **Console.** `web/consent.html` (Send, Sent, Received, Consent State, Erasure) and a login gate for it in `web.xml`. No existing page is changed. The Consent link is in the sidebar of the new page only. To support it, `list_transfers` now also returns `contract_id` and `contract_name`, and accepts optional `contract_name` and `limit` (up to 500). Existing callers are unaffected.
- **Tests.** `examples/scripts/07-consent-exchange.sh` covers the flow and the negative cases (missing `principal_id`, unknown `event_type`, wrong version, empty events, not JSON, edit and suspend of the system contract). It is part of `run-all.sh`. The 92 existing negative scenarios and the async example still pass. The screen was exercised in a headless browser across two nodes: send, receive, latest-state view, erasure request, confirmation and the reply on the sender.

Not done yet: duplicate `event_id` handling and an inactive-partner test are processor concerns (the node does not track `event_id`). Step 7 (spec, guide, CMS mapping, architecture link, changelog) and step 8 (CMS pilot) are open.

## 14. Step 7: documentation (done)

- `docs/guides/consent-exchange-format.md`: the CEF v1 spec, standalone and transport-neutral, with the processing rules, versioning rules, JSON Schema for the shape check and a reference reader.
- `docs/guides/consent-and-erasure-guide.md`: how to find the contract, bind an application, send with the Client API, receive and respect consent as a processor, run erasure, use the Consent Channel screen, and what the node does and does not do.
- `docs/guides/cef-cms-mapping.md`: field mapping to `tsi-dpdp-cms`. It records two points to settle with the CMS team: the CMS writes a new `consent_records` row on every change, so the exporter must use one stable `consent_id` per principal and fiduciary; and the CMS has a `confirm_purge_status` schema but no handler yet, so replies go through `update_purge_status`.
- `docs/design/architecture.md`: new section 15 (consent channel), data model note, code map entries and table-of-contents row.
- `CHANGELOG.md` (Unreleased), `README.md` documentation table, `examples/scripts/README.md`.
- Checked: every JSON example validates against the schema, the reference reader and the contract-id snippet run and give the expected results, and all links and anchors resolve.
- Code change made along the way: the `CEF-EVENTS` sync is now also triggered by partner status changes and by creating an application (the first draft of the guide had a fragile "created on first use" prerequisite).

