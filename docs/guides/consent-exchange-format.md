# Consent Exchange Format (CEF) v1

A small JSON format for sharing **consent**, **consent changes** and **erasure requests** between a data fiduciary's systems (for example a consent management system) and the data processors that receive the fiduciary's data. Version `1.0`.

CEF is defined here without reference to any transport. Any system that can send and receive a JSON document can use it. [TSI DX Node](../design/architecture.md#15-consent-channel-cef-events) carries it over a built-in contract; how to do that is in the [Consent and Erasure Guide](consent-and-erasure-guide.md). Mapping to the TSI DPDP consent management system is in [CEF to CMS Mapping](cef-cms-mapping.md).

The words MUST, SHOULD and MAY are used in their usual specification sense.

## 1. Model in one minute

- Consent and data travel separately. Data records carry a `principal_id`. Consent is sent as **events** that carry the same `principal_id`. The receiver (the processor) joins the two.
- Every consent event carries the **complete current state** of one consent. The latest event for a consent replaces everything earlier. Nothing is merged.
- One consent can cover several **purposes**, each with its own status.
- Erasure is a request event from the fiduciary and a confirmation event from the processor.
- The format says what happened. It never says whether processing is allowed. The processor decides that from the latest state.

## 2. Envelope

A CEF document is a JSON object. It holds one or many events, so a bulk load of consents is a single document.

```json
{ "cef_version": "1.0", "events": [ { "...": "..." } ] }
```

| Field | Required | Rule |
|---|---|---|
| `cef_version` | yes | A string `1.<minor>`. A reader MUST reject a major version it does not know. |
| `events` | yes | A non-empty array of events. |

A document is processed as a whole: if it is rejected, none of its events apply. The two parties fix the problem and resend.

## 3. Event

### 3.1 Fields on every event

| Field | Required | Meaning |
|---|---|---|
| `event_id` | yes | A string, unique per sender. A repeat of the same `event_id` from the same sender MUST have no extra effect. |
| `event_type` | yes | One of the five types in section 3.2. |
| `event_time` | yes | When the event happened, ISO 8601 in UTC (for example `2026-10-17T10:00:00Z`). |
| `fiduciary_id` | yes | A string that uniquely identifies the data fiduciary the consent belongs to. |
| `principal_id` | yes | An opaque string that identifies the data principal in the fiduciary's systems and in the data sent to the processor (a customer id, account id, vendor id). It MUST NOT be masked or hashed in the data it links to. |

Identifiers (`event_id`, `fiduciary_id`, `principal_id`, `consent_id`, `request_id`, `purpose_id`) are opaque strings. A vendor MAY use a URI or a code from another scheme. Readers MUST NOT parse them.

### 3.2 Event types

| `event_type` | Sent by | Meaning |
|---|---|---|
| `CONSENT_GRANTED` | Fiduciary | A consent was given or changed. Carries its full state, which replaces any earlier state. |
| `CONSENT_WITHDRAWN` | Fiduciary | A consent was withdrawn, in whole or in part. Carries its new full state. |
| `ERASURE_REQUESTED` | Fiduciary | The principal's data is to be erased. |
| `ERASURE_CONFIRMED` | Processor | Reply to an erasure request. |

The two consent types differ only in why the state changed. A reader MUST apply both the same way (section 4).

### 3.3 Consent events

`CONSENT_GRANTED` and `CONSENT_WITHDRAWN` carry:

| Field | Required | Meaning |
|---|---|---|
| `consent_id` | yes | Identifies the consent. One consent can cover several purposes. |
| `granted_at` | yes | When the principal gave the consent, ISO 8601 UTC. |
| `purposes` | yes | Array of purposes (section 3.4). This is the complete current state. |

### 3.4 Purposes

| Field | Required | Meaning |
|---|---|---|
| `purpose_id` | yes | A unique string for the purpose. A data contract or data feed names the `purpose_id` it serves. |
| `status` | yes | `granted`, `denied`, `withdrawn` or `expired`. |
| `expires_at` | no | When the consent for this purpose lapses, ISO 8601 UTC. Empty or absent means until withdrawn. |
| `data_categories` | no | Array of strings naming the data this purpose covers. |

### 3.5 `ERASURE_REQUESTED`

| Field | Required | Meaning |
|---|---|---|
| `request_id` | yes | Identifies the request. The reply uses the same id. |
| `trigger` | yes | Why: `ErasureRequest`, `ConsentWithdrawal` or `RetentionPolicyExpiry`. |
| `deadline_at` | yes | When erasure must be complete, ISO 8601 UTC. Set by the fiduciary for each request. |
| `purpose_ids` | no | Array. Limits erasure to data held for these purposes. Empty or absent means all purposes. |
| `data_categories` | no | Array. Limits erasure to these categories. Empty or absent means all categories. |

An erasure request with neither `purpose_ids` nor `data_categories` means everything held about the principal. That is deliberate.

### 3.6 `ERASURE_CONFIRMED`

| Field | Required | Meaning |
|---|---|---|
| `request_id` | yes | The request being answered. |
| `reply_status` | yes | `ACKNOWLEDGED`, `COMPLETED`, `REJECTED`, `UNDER_LEGAL_HOLD` or `FAILED`. |
| `records_affected_count` | no | Number of records erased. |
| `details`, `error_message` | no | Free text, for example a legal-hold reason or why the request was rejected. |
| `confirmed_by` | no | Who at the processor confirmed. |
| `confirmed_at` | no | ISO 8601 UTC. |

A processor MAY send more than one reply for a request (for example `ACKNOWLEDGED`, then `COMPLETED`). The latest by `event_time` is the current one.

## 4. Processing rules

These apply to whoever consumes events. They are what lets two independent implementations agree.

1. **Latest state wins.** For each `consent_id` (within a `fiduciary_id` and `principal_id`), the consent event with the latest `event_time` replaces the whole earlier state. If two events have the same `event_time`, the later one in delivery order wins. An event older than the one already applied is ignored.
2. **Full state, no merging.** A purpose that is not in the latest state is not consented. To withdraw one purpose, send the full state with that purpose set to `withdrawn`. To withdraw everything, send every purpose as `withdrawn`.
3. **Idempotent.** A repeated `event_id` from the same sender, and a repeated `request_id`, MUST NOT change the outcome.
4. **Processing is allowed only on a granted purpose.** A processor SHOULD use a principal's data for a purpose only while the latest state for that purpose is `granted` and `expires_at` has not passed. A processor SHOULD hold or reject data for which it has no granted consent.
5. **Erasure only for data the processor holds.** A processor SHOULD act on an erasure request only for principals whose data it received from that fiduciary, and SHOULD answer `REJECTED` otherwise.
6. **Unknown content is ignored.** Within `1.x`, a reader MUST ignore fields it does not know and event types it does not know.

## 5. What a sender or relay checks

A relay (such as DX Node) that moves CEF documents SHOULD check only the shape, and MUST NOT judge consent. The shape check is:

- the document is valid JSON and an object;
- `cef_version` matches `1.<minor>`;
- `events` is a non-empty array;
- every event has non-empty string values for `event_id`, `event_type`, `event_time`, `fiduciary_id` and `principal_id`, and `event_type` is one of the five types.

The per-type fields in sections 3.3 to 3.6 are checked by the receiving application.

## 6. Versioning and compatibility

- Within `1.x`, new fields are additive and optional, and new event types may be added. A `1.0` reader MUST keep working on a `1.x` document by ignoring what it does not know.
- A change that removes or renames a field, or changes what a field means, requires `cef_version` `2.0`.
- Version `1.0` field names and meanings are fixed.

## 7. Examples

### 7.1 Grant with two purposes

```json
{ "cef_version": "1.0", "events": [
  { "event_id": "e-1", "event_type": "CONSENT_GRANTED", "event_time": "2026-10-01T09:00:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3",
    "consent_id": "c-77", "granted_at": "2026-10-01T09:00:00Z",
    "purposes": [
      { "purpose_id": "loan_underwriting", "status": "granted",
        "expires_at": "2027-10-01T09:00:00Z", "data_categories": ["income", "pan"] },
      { "purpose_id": "credit_marketing", "status": "granted", "data_categories": ["email"] } ] } ] }
```

### 7.2 Withdraw one purpose (full new state)

```json
{ "cef_version": "1.0", "events": [
  { "event_id": "e-2", "event_type": "CONSENT_WITHDRAWN", "event_time": "2026-10-17T10:00:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3",
    "consent_id": "c-77", "granted_at": "2026-10-01T09:00:00Z",
    "purposes": [
      { "purpose_id": "loan_underwriting", "status": "granted",
        "expires_at": "2027-10-01T09:00:00Z", "data_categories": ["income", "pan"] },
      { "purpose_id": "credit_marketing", "status": "withdrawn", "data_categories": ["email"] } ] } ] }
```

### 7.3 Erasure request and reply

```json
{ "cef_version": "1.0", "events": [
  { "event_id": "e-3", "event_type": "ERASURE_REQUESTED", "event_time": "2026-10-17T10:05:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3",
    "request_id": "r-31", "trigger": "ErasureRequest",
    "purpose_ids": ["credit_marketing"], "deadline_at": "2026-10-27T10:05:00Z" } ] }
```

```json
{ "cef_version": "1.0", "events": [
  { "event_id": "e-9", "event_type": "ERASURE_CONFIRMED", "event_time": "2026-10-20T08:00:00Z",
    "fiduciary_id": "f-1001", "principal_id": "p-9a3",
    "request_id": "r-31", "reply_status": "COMPLETED", "records_affected_count": 4,
    "details": "Marketing records deleted", "confirmed_by": "processor-ops",
    "confirmed_at": "2026-10-20T08:00:00Z" } ] }
```

## 8. JSON Schema for the shape check

This is the schema DX Node applies (JSON Schema draft-07). It checks only the shape in section 5. Unknown fields are allowed.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["cef_version", "events"],
  "properties": {
    "cef_version": { "type": "string", "pattern": "^1\\.[0-9]+$" },
    "events": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["event_id", "event_type", "event_time", "fiduciary_id", "principal_id"],
        "properties": {
          "event_id":     { "type": "string", "minLength": 1 },
          "event_type":   { "type": "string", "enum": ["CONSENT_GRANTED", "CONSENT_WITHDRAWN", "ERASURE_REQUESTED", "ERASURE_CONFIRMED"] },
          "event_time":   { "type": "string", "minLength": 1 },
          "fiduciary_id": { "type": "string", "minLength": 1 },
          "principal_id": { "type": "string", "minLength": 1 }
        }
      }
    }
  }
}
```

## 9. Reference reader

A processor needs only a few lines to turn a stream of events into current state. This sketch keeps the latest consent event per `(fiduciary_id, principal_id, consent_id)` and answers whether a purpose may be used.

```python
import json
from datetime import datetime, timezone

state = {}   # (fiduciary, principal, consent) -> latest consent event

def apply(document: str):
    doc = json.loads(document)
    for e in doc["events"]:
        if not e["event_type"].startswith("CONSENT_"):
            continue
        key = (e["fiduciary_id"], e["principal_id"], e["consent_id"])
        cur = state.get(key)
        if cur is None or e["event_time"] >= cur["event_time"]:   # same time: later event wins
            state[key] = e

def allowed(fiduciary, principal, purpose_id, now=None):
    now = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for (f, p, _), e in state.items():
        if f == fiduciary and p == principal:
            for pu in e["purposes"]:
                if pu["purpose_id"] == purpose_id and pu["status"] == "granted" \
                        and not (pu.get("expires_at") and pu["expires_at"] <= now):
                    return True
    return False
```

(String comparison of `event_time` is correct while every timestamp is ISO 8601 in UTC with a `Z` suffix and the same precision. A production reader should parse timestamps.)

## 10. Status

CEF `1.0` is the first version. Its field names and meanings are fixed; see section 6 for how it may grow. Feedback and extensions from other vendors are welcome and will be considered for `1.x` additions or `2.0`.
