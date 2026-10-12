#!/usr/bin/env bash
# Step 5 - Synchronous call (real-time lane).
#
# An application on Node A calls execute_sync_request. Node A governs the request, calls Node B
# over HTTPS, Node B forwards it to the contract's responder service and returns a governed
# response - all inside one request, within the contract's timeout.
#
#   1. Creates (once) an application on Node A authorised for the sync contract + an API key.
#   2. execute_sync_request -> prints response_payload and duration_ms.
#   3. Prints the per-call audit row recorded on each node (sync_audit_log).
#
# Needs a responder at the contract's sync_responder_url. The compose file starts a mock that
# answers {"result":"ok"} to any POST; point SYNC_RESPONDER_URL at a real service when creating
# the contract in step 3 to see real answers.
#
# Requires: curl, jq. Run 01-03 first.
#
# Usage:
#   ./05-sync-call.sh [payload.json]     (default: payloads/sync-sample.json)
#   ./05-sync-call.sh --invalid          sends a payload that breaks the contract schema (expects 400)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_tools

INVALID=0
if [ "${1:-}" = "--invalid" ]; then INVALID=1; shift; fi
FILE="${1:-$EXAMPLES_DIR/payloads/sync-sample.json}"
[ -r "$FILE" ] || die "Payload file not found: $FILE"
if [ "$INVALID" = 1 ]; then PAYLOAD='{"customer_id":"C-001"}'; else PAYLOAD="$(jq -c . "$FILE")" || die "$FILE is not valid JSON"; fi

CID="$(state_need sync_contract_id ./03-define-contract.sh)" || exit 1

step "Application and API key (Node A)"
ensure_app_key sync "$CID"
KEY="$(state_get sync_api_key)"; SECRET="$(state_get sync_api_secret)"

step "execute_sync_request"
IDEM="example-$(date +%s)"
info "request:  $PAYLOAD"
client "$NODE_A_URL" "$KEY" "$SECRET" "$(jq -n --arg c "$CID" --argjson p "$PAYLOAD" --arg i "$IDEM" \
  '{_func:"execute_sync_request",contract_id:$c,request_payload:$p,idempotency_key:$i}')"

if [ "$INVALID" = 1 ]; then
  [ "$CODE" = "400" ] || die "Expected HTTP 400 for an invalid payload, got $CODE"
  ok "Rejected with HTTP 400 as expected: $(printf '%s' "$RESP" | jq -r .message)"
  exit 0
fi
[ "$CODE" = "200" ] || die "Sync call failed (HTTP $CODE): $(printf '%s' "$RESP" | jq -r '.message // .')"
ok "response: $(printf '%s' "$RESP" | jq -c .response_payload)"
ok "duration: $(printf '%s' "$RESP" | jq -r .duration_ms) ms"

step "Audit trail (sync_audit_log)"
show_audit() {   # label url
  local jwt; jwt="$(login "$2")" || exit 1
  admin "$2" "$jwt" transfers '{"_func":"list_sync_audit_logs"}'
  printf '%s' "$RESP" | jq -r --arg k "$IDEM" --arg l "$1" \
    '.data[]|select(.idempotency_key==$k)|"    \($l): \(.status) \(.duration_ms)ms  request=\(.request_payload|tojson)"' | head -n1
}
show_audit "Node A (caller)  " "$NODE_A_URL"
show_audit "Node B (receiver)" "$NODE_B_URL"
info "Payloads in the log are post-governance: the mobile number is masked."
