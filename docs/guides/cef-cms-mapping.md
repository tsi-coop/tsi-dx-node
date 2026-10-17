# CEF to CMS Mapping

How the TSI DPDP consent management system (`tsi-dpdp-cms`) maps to the [Consent Exchange Format (CEF)](consent-exchange-format.md), for the team that writes the CMS export and the import of replies. CEF field names were chosen to follow the CMS, so most of this is a direct copy.

Source of truth for the CMS side: `db/01_init.sql` (`consent_records`, `purge_requests`) and the request schemas under `web/WEB-INF/validator/` (`record_consent`, `withdraw_consent`, `erasure_request`, `update_purge_status`). Where this page and the CMS code disagree, the CMS code wins and this page should be corrected.

## 1. Outbound: CMS to processor

The CMS exporter turns CMS changes into CEF events and submits them to the processor node's `CEF-EVENTS` ([guide](consent-and-erasure-guide.md) §4). One document can hold many events.

### 1.1 Common fields

| CEF field | CMS source |
|---|---|
| `event_id` | Generate a unique id per event (a UUID). Keep it, so a resend can reuse it. |
| `event_time` | `consent_records.timestamp` for consent events (when consent was given or updated); the time of the request for erasure |
| `fiduciary_id` | `consent_records.fiduciary_id` / `purge_requests.fiduciary_id` (as a string) |
| `principal_id` | `consent_records.user_id` / `purge_requests.user_id`. This is the CMS link key and must be the same id the data feed carries. |

### 1.2 Consent events

| CEF field | CMS source |
|---|---|
| `consent_id` | See the **stable id** rule below |
| `granted_at` | `consent_records.timestamp` |
| `purposes[]` | Built from `consent_records.data_point_consents`, grouped by `purpose_agreed_to` |
| `purposes[].purpose_id` | `data_point_consents[].purpose_agreed_to` |
| `purposes[].status` | `granted` when at least one data point for the purpose has `consent_granted = true`; otherwise `denied` (never granted) or `withdrawn` (previously granted) |
| `purposes[].data_categories` | The `data_point_id` of each data point with `consent_granted = true` for that purpose |
| `purposes[].expires_at` | The expiry of the consent policy or retention rule for the purpose, if the CMS holds one; otherwise omit |

**Event type** comes from what happened in the CMS:

| CMS action | CEF `event_type` |
|---|---|
| `record_consent` for a principal with no earlier consent for this fiduciary | `CONSENT_GRANTED` |
| `record_consent` that changes an existing consent | `CONSENT_MODIFIED` |
| `withdraw_consent` (all purposes, or the `purpose_ids` given) | `CONSENT_WITHDRAWN` |

**Stable `consent_id`.** The CMS keeps one active consent per principal and fiduciary and writes a **new** `consent_records` row (new `id`) on every change, marking the old one inactive. CEF replaces state per `consent_id`, so if the exporter used the row `id`, the processor would keep the old consent's `granted` state forever. Use one `consent_id` for the principal-and-fiduciary pair for as long as it lives, for example the `id` of the first `consent_records` row for that `(user_id, fiduciary_id)`. Every later change then replaces the previous state.

**Always send the full state.** After a withdrawal of one purpose, export the principal's complete current purposes list with that purpose `withdrawn`, not only the changed purpose. The CMS already stores the full `data_point_consents` for the new record, so export that.

### 1.3 Erasure request

Erasure requests and withdrawals lead the CMS to create rows in `purge_requests` (through its erasure service). Export each such row as `ERASURE_REQUESTED`:

| CEF field | CMS source |
|---|---|
| `request_id` | `purge_requests.id` |
| `trigger` | `purge_requests.trigger_event` (`ErasureRequest`, `ConsentWithdrawal`, `RetentionPolicyExpiry`) |
| `purpose_ids` | `purge_requests.purpose_id`, or `processing_purposes_affected` when the request carries a list. Omit for everything. |
| `data_categories` | `data_categories_to_purge`, if present. Omit for everything. |
| `deadline_at` | The statutory or policy deadline the CMS applies to this request. Set per request. |

## 2. Inbound: processor reply to CMS

The CMS reads `ERASURE_CONFIRMED` events from its own `CEF-EVENTS` (a received transfer, [guide](consent-and-erasure-guide.md) §5) and updates the purge request whose id equals `request_id`.

| CEF field | CMS target |
|---|---|
| `request_id` | `purge_requests.id` (the `id` in `update_purge_status`) |
| `reply_status` | `status`, mapped below |
| `details`, `error_message`, `records_affected_count`, `confirmed_by`, `confirmed_at` | `details` (one text field; combine them, for example `"COMPLETED by processor-ops at 2026-10-20T08:00:00Z, 4 records. Marketing records deleted"`) |

| `reply_status` | `purge_requests.status` |
|---|---|
| `ACKNOWLEDGED` | `IN_PROGRESS` |
| `COMPLETED` | `COMPLETED` |
| `UNDER_LEGAL_HOLD` | `UNDER_LEGAL_HOLD` |
| `REJECTED` | `FAILED`, with the reason in `details` |
| `FAILED` | `FAILED` |

Call `update_purge_status` with `id`, `status` and `details`. The CMS also ships a `confirm_purge_status` request schema (`purge_request_id`, `status`, `records_affected_count`, `details`, `error_message`, `confirmed_by_entity_id`) whose fields line up with `ERASURE_CONFIRMED`, but at the time of writing the CMS has no handler for it, so use `update_purge_status`. When that handler exists, `records_affected_count`, `error_message` and `confirmed_by` can map to its own fields instead of being packed into `details`.

A processor may send several replies for one request. Apply them in `event_time` order and keep the latest.

## 3. Things to settle with the CMS team

| Question | Suggested answer |
|---|---|
| Which id is the stable `consent_id`? | The first `consent_records.id` for the `(user_id, fiduciary_id)` pair (section 1.2). Store it so it never changes. |
| Where does `expires_at` come from? | Consent policy or retention policy, if it defines a lifetime. Omit when there is none. |
| Which purposes does a data feed serve? | The data contract's name or description carries the `purpose_id`. It must equal the CMS purpose id used in `purpose_agreed_to`. |
| Does the CMS need delivery receipts? | `get_transfer_status` returns `Delivered` when the partner node has accepted the file. The processor's `ERASURE_CONFIRMED` is the business-level reply for erasure. |
| Who runs the exporter? | A small job or hook next to the CMS that calls the DX Node Client API (`initiate_transfer`) per change or per night. It is outside both products. |
