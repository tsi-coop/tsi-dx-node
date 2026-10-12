#!/usr/bin/env bash
# Step 4 - Asynchronous transfer (batch lane).
#
# An application on Node A hands a JSON package to its node through the Client API. The node
# stages it, applies the contract's L1 validation and L2 PII rules, sequences it and delivers it
# to Node B in the background. The script then polls until delivery and shows what Node B stored.
#
#   1. Creates (once) an application on Node A authorised for the async contract + an API key.
#   2. initiate_transfer          -> returns a transfer_id immediately (status Pending).
#   3. get_transfer_status        -> polled until Delivered / Failed.
#   4. Node B list_transfers      -> the same transfer as Received.
#   5. Node B get_transfer_payload-> the governed payload as stored (PII transformed).
#
# Requires: curl, jq. Run 01-03 first.
#
# Usage:  ./04-async-transfer.sh [payload.json]       (default: payloads/async-sample.json)
#
# Re-run it to send more packages: each gets the next sequence number.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
require_tools

FILE="${1:-$EXAMPLES_DIR/payloads/async-sample.json}"
[ -r "$FILE" ] || die "Payload file not found: $FILE"
jq empty "$FILE" 2>/dev/null || die "$FILE is not valid JSON"

CID="$(state_need async_contract_id ./03-define-contract.sh)" || exit 1

step "Application and API key (Node A)"
ensure_app_key async "$CID"
KEY="$(state_get async_api_key)"; SECRET="$(state_get async_api_secret)"

step "Initiate transfer"
NAME="$(basename "${FILE%.json}")-$(date +%s).json"
client "$NODE_A_URL" "$KEY" "$SECRET" "$(jq -n --arg c "$CID" --arg n "$NAME" --arg d "$(b64 "$FILE")" \
  '{_func:"initiate_transfer",contract_id:$c,file_name:$n,file_data:$d}')"
[ "$CODE" = "201" ] || [ "$CODE" = "200" ] || die "initiate_transfer failed (HTTP $CODE): $(printf '%s' "$RESP" | jq -r '.message // .')"
TID="$(printf '%s' "$RESP" | jq -r .transfer_id)"
ok "Accepted: transfer_id=$TID"

step "Track delivery (Node A)"
transfer_done() {
  client "$NODE_A_URL" "$KEY" "$SECRET" "$(jq -n --arg t "$TID" '{_func:"get_transfer_status",transfer_id:$t}')"
  STATUS="$(printf '%s' "$RESP" | jq -r '.status // empty')"
  case "$STATUS" in Delivered|Failed) return 0 ;; *) return 1 ;; esac
}
wait_for transfer_done || die "Transfer still '$STATUS' after ${WAIT_SECS:-60}s"
if [ "$STATUS" = "Failed" ]; then die "Transfer failed: $(printf '%s' "$RESP" | jq -r .error)"; fi
ok "Status: $STATUS"

step "Verify on the receiver (Node B)"
TOKEN_B="$(login "$NODE_B_URL")" || exit 1
admin "$NODE_B_URL" "$TOKEN_B" transfers '{"_func":"list_transfers"}'
RECV="$(printf '%s' "$RESP" | jq -r --arg t "$TID" '.data[]|select(.transfer_id==$t)|.status')"
[ "$RECV" = "Received" ] || die "Node B shows status '${RECV:-<missing>}' for $TID"
ok "Node B status: Received"

admin "$NODE_B_URL" "$TOKEN_B" transfers "$(jq -n --arg t "$TID" '{_func:"get_transfer_payload",transfer_id:$t}')"
info "Payload as stored on Node B (governed - PII transformed per the contract):"
printf '%s' "$RESP" | jq -r '.payload' | jq . | sed 's/^/      /'
state_set last_async_transfer_id "$TID"
